Return-Path: <kasan-dev+bncBCM3H26GVIOBB76N3OVQMGQENNHJDVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 885C880C6DC
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 11:40:01 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-58d76712504sf5212592eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 02:40:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702291200; cv=pass;
        d=google.com; s=arc-20160816;
        b=mv/i+Cbk9XPa1n/4Jk4oqhKd3ijqp7lUIcWIBmo75j1ByBaROzKbNCHAdFQbGws0DO
         sWrm9Xk+S9GqowLNFoErGH94IfPhdOzfy80/dgbD2mQv9KXV+t/8xQRMzLlE/lkj7JXo
         dvnJ5u9wpwrT3MJP97MPWZxe4+/148lfBviyz9XImdpIe425NyYkJ0rfUt0mK9/FQs9F
         yW6mw+dp1TqgsJG2rWY77U/ZRAw3dtAg4HkhfoHyDWmVF1LUwMBqz6IDr8BT9XHa3lLQ
         hZDJo4QnYlDOCjEl35gHPkny69KBjoSgvnpEYPMgN4XDqR+x37c9xh/k2kLJY5fgmxsl
         Noxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=o0W8LoGeJEPKw8pJ1Fo9BCC9dI0O9HWbpzy+1UN+EVQ=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=KvZfY/WR8iyTs5WUUDeXRTRG0NIgc2adem5eC9kOOnzIwwWAwMhiaE/RJrK5tiRc/2
         RJIoUmRQ7xVTzQVtp3Hf73oqCKtbeAVz7GrVY+OZt2sgf82swPFtBj8b3LlpGwvCHPKc
         BArcSqD5YowLdtJiLwOVL/JC5rLwd7ZnxIBmxAXShdgbkMuk3sXsCkl/kvdoMv9RoCpr
         yz4dzPc+/trSx4dg2u/yAYX7R63HUBJGKql4JZrs03PZuouwobLmMb3wU6UY3uHhAtbW
         iFVK7itwFZJYr7iKnDZ/8JpgBYSmWQxu5+6AWhmNAtrRGYVzxYxfEECjHwNFOCMSI3XF
         UKbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="cKZ/RnKA";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702291200; x=1702896000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=o0W8LoGeJEPKw8pJ1Fo9BCC9dI0O9HWbpzy+1UN+EVQ=;
        b=T+OgHp69WKZpjjVlT/FFdPdHsR2Zwh42LrajNXckJIMUgw6bq0WEJ9+QQYNvZz21Rv
         aEfV80MM+2gtuvAiwLwEsADF61EmMnoEXYnoqX3CCKjeaXUwtXmckyd5TXvJ5dgOqYPC
         9NFMSTiMgOh4f3fV5obH36XNjT83FQAWV4z6ySDzNJ4sPR4DvE66JURKZTESkRzGZN6r
         4BXSXl6b8VxxM2qdjFxN+eBnisJnndWv3uDCB68sxgSabp1eRsgPxI+KgzeJQsvw759g
         OOHDGzNkPeA72x3PRLECKaAKc7n6RNgYiAIqnURl1SvLpyp99FaOsli2gomuXelUWyb3
         K5eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702291200; x=1702896000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=o0W8LoGeJEPKw8pJ1Fo9BCC9dI0O9HWbpzy+1UN+EVQ=;
        b=kYtokvQKWPfPkV85oefPyA79tEc4SIQKRq6Qc6YrnSNnv5+sEJYAgmL0hV0mhCcoNk
         x6l0lmh4iNYhxO5wyBI9ATn32YwcXGNamGvNVRTQPI3ayCSs41gk8Q8Qs2V7gu9H+X2F
         6Dh2G02Wny6cxsfByS71T7fHeqwmF3CVkSom15HMF8DGSx8uTfOY+2Ee0f7y82RFZL7Z
         PcmM9odY3sv+qO3Qghs5vw9OYZd1dNvhYOsGsjj6WeZ0S9rPhoRwJl7bhAftR0a2yu5K
         oIecpUpqFunG6E+LjMFUiqsEzzvicwq4Cg7o35hgDhp2QKz57YS+pgQAE9h55Ar9BO6Z
         kYNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxMewwaAAt26lOZZWfZOKa5Xc6AtUKrPDo1zTXST13p8XnwRBhZ
	UIgN2hqq6PT04Cxr9z60Nyk=
X-Google-Smtp-Source: AGHT+IFqB23+cuULfYxBP1w66Lb/1/NC7LXIwvXvvssOmiitcRXmf1wCQ50xH5ZmToMpqNNDRyiOLw==
X-Received: by 2002:a05:6870:5aaa:b0:1e9:f0fe:6ba4 with SMTP id dt42-20020a0568705aaa00b001e9f0fe6ba4mr3973551oab.11.1702291199997;
        Mon, 11 Dec 2023 02:39:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9a21:b0:1fa:1717:fc5a with SMTP id
 fo33-20020a0568709a2100b001fa1717fc5als360566oab.1.-pod-prod-08-us; Mon, 11
 Dec 2023 02:39:59 -0800 (PST)
X-Received: by 2002:a05:6870:cb8b:b0:1f0:d96:8d9c with SMTP id ov11-20020a056870cb8b00b001f00d968d9cmr6374665oab.9.1702291199329;
        Mon, 11 Dec 2023 02:39:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702291199; cv=none;
        d=google.com; s=arc-20160816;
        b=uGw0wLySxCjnuKp2xEpsDc1CW0RofrzEzbYM2P0eHJ9dXYNonlUredH7zU6EG+PM+l
         QNONf2ArpMbmSsTpgvXhTxruSWHO1o1Uo4bOQaCQXHBviV2eG9QArbOC/WjTbyQeAc4b
         fPC38lIiBH5tjO0sKKN1Z3auB4+gaSeuYzwewV8SpkGRCucsO5q3NlylNwbFETGV9gu8
         Nd6anixtrVuJ9yCVSpc+ueeWNiXJt6su66tKLZItdlwB13JSxXcxdvFLNisV/JHFU5Rd
         B88QAmQPe02aNj2QId3wjb9zDiqzxo/ogO2wkWXKii97HHChsKgWptjasJf4vxPrF4dO
         jCjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=yVHr17YdvQe0ydCo0BKzg0tAiF/vmW+T/J/qFqM2G7w=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=jJisde1Za21YJP+v5o1INt/tfQ027N8A0oFOigriegQMtCP/4zgGEJfpZntB+SPZjn
         tCx4y39BW7ulusmQQ3kYSTIrPoKt3YFXJxKZxdzXa5eygmtM8bT6xTr72givjkoEmVjE
         qj/PfxP3PWBrGBR5e8wgCN5jQ+O4Qk9wkHRAAtp92aOBWgz3Y669GXpv1MJ3gLdz+CUE
         HYGKvYUpny6Z+Gj8h2Adyka3xyGE59xX5B1+0FQR2/LElZNRs/GVWpcBxPdprF0KT9RA
         qZ6V0oPmPZkQ2c4bps54axRhWApuRfCxb90W+0rN3rFMx5hsGg4v4/UTougWFPBvGAil
         ZIkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="cKZ/RnKA";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id hx10-20020a056871530a00b001fb179a3c63si814138oac.3.2023.12.11.02.39.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Dec 2023 02:39:59 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BBAMu3T015214;
	Mon, 11 Dec 2023 10:39:54 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ux0m50d6n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 11 Dec 2023 10:39:54 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BBAMv4L015310;
	Mon, 11 Dec 2023 10:39:53 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ux0m50d68-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 11 Dec 2023 10:39:53 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BB9FbH0004701;
	Mon, 11 Dec 2023 10:39:52 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4sk0cg3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 11 Dec 2023 10:39:52 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BBAdnC017236688
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Dec 2023 10:39:49 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 621BD20043;
	Mon, 11 Dec 2023 10:39:49 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4276B20040;
	Mon, 11 Dec 2023 10:39:48 +0000 (GMT)
Received: from [9.171.76.38] (unknown [9.171.76.38])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Mon, 11 Dec 2023 10:39:48 +0000 (GMT)
Message-ID: <13e3e073f6ed6aa48b39ec16add85baa677d17b4.camel@linux.ibm.com>
Subject: Re: [PATCH v2 32/33] s390: Implement the architecture-specific
 kmsan functions
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Andrew Morton
 <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>,
        David
 Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo
 Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami
 Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven
 Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil
 Babka <vbabka@suse.cz>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle
 <svens@linux.ibm.com>
Date: Mon, 11 Dec 2023 11:39:47 +0100
In-Reply-To: <CAG_fn=V5zMxGUQ=KmJh-ghTUHa-AZYn1CPTQNbf3x7Lu0w=HvA@mail.gmail.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
	 <20231121220155.1217090-33-iii@linux.ibm.com>
	 <CAG_fn=V5zMxGUQ=KmJh-ghTUHa-AZYn1CPTQNbf3x7Lu0w=HvA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 1ivu9TPpbV33bJspuyHdGPksD1bDTXIu
X-Proofpoint-GUID: NVWxg9UEFQWh9310drT6RwvUw1xWNTKv
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-11_04,2023-12-07_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0
 mlxlogscore=313 spamscore=0 impostorscore=0 bulkscore=0 priorityscore=1501
 lowpriorityscore=0 adultscore=0 mlxscore=0 phishscore=0 malwarescore=0
 clxscore=1011 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312110086
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="cKZ/RnKA";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

T24gTW9uLCAyMDIzLTEyLTExIGF0IDExOjI2ICswMTAwLCBBbGV4YW5kZXIgUG90YXBlbmtvIHdy
b3RlOgo+ID4gK3N0YXRpYyBpbmxpbmUgdm9pZCAqYXJjaF9rbXNhbl9nZXRfbWV0YV9vcl9udWxs
KHZvaWQgKmFkZHIsIGJvb2wKPiA+IGlzX29yaWdpbikKPiA+ICt7Cj4gPiArwqDCoMKgwqDCoMKg
IGlmIChhZGRyID49ICh2b2lkICopJlMzOTBfbG93Y29yZSAmJgo+ID4gK8KgwqDCoMKgwqDCoMKg
wqDCoMKgIGFkZHIgPCAodm9pZCAqKSgmUzM5MF9sb3djb3JlICsgMSkpIHsKPiA+ICvCoMKgwqDC
oMKgwqDCoMKgwqDCoMKgwqDCoMKgIC8qCj4gPiArwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDC
oMKgICogRGlmZmVyZW50IGxvd2NvcmVzIGFjY2Vzc2VkIHZpYSBTMzkwX2xvd2NvcmUgYXJlCj4g
PiBkZXNjcmliZWQKPiA+ICvCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqAgKiBieSB0aGUg
c2FtZSBzdHJ1Y3QgcGFnZS4gUmVzb2x2ZSB0aGUgcHJlZml4Cj4gPiBtYW51YWxseSBpbgo+ID4g
K8KgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoCAqIG9yZGVyIHRvIGdldCBhIGRpc3RpbmN0
IHN0cnVjdCBwYWdlLgo+ID4gK8KgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoCAqLwo+ID4g
K8KgwqDCoMKgwqDCoMKgwqDCoMKgwqDCoMKgwqAgYWRkciArPSAodm9pZCAqKWxvd2NvcmVfcHRy
W3Jhd19zbXBfcHJvY2Vzc29yX2lkKCldCj4gPiAtCj4gPiArwqDCoMKgwqDCoMKgwqDCoMKgwqDC
oMKgwqDCoMKgwqDCoMKgwqDCoMKgwqAgKHZvaWQgKikmUzM5MF9sb3djb3JlOwo+ID4gK8KgwqDC
oMKgwqDCoMKgwqDCoMKgwqDCoMKgwqAgcmV0dXJuIGttc2FuX2dldF9tZXRhZGF0YShhZGRyLCBp
c19vcmlnaW4pOwo+ID4gK8KgwqDCoMKgwqDCoCB9Cj4gPiArwqDCoMKgwqDCoMKgIHJldHVybiBO
VUxMOwo+ID4gK30KPiAKPiBJcyB0aGVyZSBhIHBvc3NpYmlsaXR5IGZvciBpbmZpbml0ZSByZWN1
cnNpb24gaGVyZT8gRS5nLiBjYW4KPiBgbG93Y29yZV9wdHJbcmF3X3NtcF9wcm9jZXNzb3JfaWQo
KV1gIHBvaW50IHNvbWV3aGVyZSBpbiBiZXR3ZWVuCj4gYCh2b2lkICopJlMzOTBfbG93Y29yZWAg
YW5kIGAodm9pZCAqKSgmUzM5MF9sb3djb3JlICsgMSkpYD8KCk5vLCBpdCdzIGFsbG9jYXRlZCB3
aXRoIF9fZ2V0X2ZyZWVfcGFnZXMoKSBvciBtZW1ibG9ja19hbGxvY19sb3coKS4KQnV0IHNpbmNl
IHRoaXMgcXVlc3Rpb24gY2FtZSB1cCwgSSBzaG91bGQgcHJvYmFibHkgYWRkIGEgY2hlY2sgYW5k
CmEgV0FSTl9PTl9PTkNFKCkgaGVyZS4KDQotLSAKWW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBi
ZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAia2FzYW4tZGV2
IiBncm91cC4KVG8gdW5zdWJzY3JpYmUgZnJvbSB0aGlzIGdyb3VwIGFuZCBzdG9wIHJlY2Vpdmlu
ZyBlbWFpbHMgZnJvbSBpdCwgc2VuZCBhbiBlbWFpbCB0byBrYXNhbi1kZXYrdW5zdWJzY3JpYmVA
Z29vZ2xlZ3JvdXBzLmNvbS4KVG8gdmlldyB0aGlzIGRpc2N1c3Npb24gb24gdGhlIHdlYiB2aXNp
dCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2LzEzZTNlMDczZjZl
ZDZhYTQ4YjM5ZWMxNmFkZDg1YmFhNjc3ZDE3YjQuY2FtZWwlNDBsaW51eC5pYm0uY29tLgo=
