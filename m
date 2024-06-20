Return-Path: <kasan-dev+bncBCVZXJXP4MDBBOHL2CZQMGQEZUXAI7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C2D991070A
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 15:59:22 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1f851ea7a09sf6614915ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 06:59:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718891960; cv=pass;
        d=google.com; s=arc-20160816;
        b=dxWoq92OUH7UmeuRRD/Ru69G2H+18VO7tcsv7F5NcUYt4XdQc5rEFN8lrv8g2n1kKT
         Cpe9jm1xilYDaqD9zuvHxQbTj8qP1q7X2/olqklCWFLlhEihxVP/JHP5A9Un4x+hcj7J
         7ERgKX9XBNvnRTAOjl6Ow65JHbqb7Y11GgqBt69hizjWMNA//UWUVJudrWpOk+cr0YN3
         9/0e2el7oQ7aIrSYoxhYj+KSO58h7zl2lib+35nTF2vyryYfKsIP94cuplwRaZyuQYrb
         jsNeyAp4JF21xnbziQLqpd6EGG20mz7m0EDmSYXewytsDAptnM27oP06iEkE3W+q7JEc
         Lxcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+xi4mZasi5vm4eg4cEoIT9vHFsfqAaLD6QdORB3MuHc=;
        fh=stQs2TylBcxpYuKEWYB2f/FKYH7XyFCZaUTBbODPok4=;
        b=qi8puiHpiqQ7KRbG5SXHJg4on08dM5tqqKwSqbOJc5TaARW1R+1zD1urwEnK1vIyPL
         +ZFYbPQq9Ciakw1NcT3fYym+x33wUK5jxZj7mTsBbidwauiYM8JkxcIBXK3HY6/Jso2b
         uAJSeic8Um1Gp183WiTRqfR3eeTMZtzhbHIYf86KfO65TRUTZ3HGeglEHAehzUInYqD0
         4cGAuv6JJgkXiabAFSsuIzZJ9YXNQqXWXAE2WB94h6GdFdaRR/Nu0zU6xBYEwDvM3TUf
         oe8lrGZgX95BO/hBVmVpRgMKONEbEOJ/RC1018dHSHQTXl/GAMiMFQsafABPOO79OJNE
         l0LA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=XOKXz9J4;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718891960; x=1719496760; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+xi4mZasi5vm4eg4cEoIT9vHFsfqAaLD6QdORB3MuHc=;
        b=ZZVwLjPIR46iD8ORygLoNn7IiMiJQQSR1FRc63q2qV3nhgE06XgFuENW3M0UOP4I4k
         1V1ccdrMZjMwuJshZClZ72QBT/G05UfZHyVvT5hJSKdWT740U8yXiCD9D5XTc7EE8H9h
         PjoQe8NG5rxY1BhSt094gXpdAjl+aGXoABWes/B/y9LWIA7tXbSfDPpgv+29BgyvQEvL
         v3k9HvV6a91g8gucVwVqa1Q0e9n4ZoCn1yt84C8zeJUhgxv5NZ7tVvH9WAKt0Bg9s7BN
         vFCsG4X1V1Tn/B8msmZSsw+FBSWQ0fBZQfhvR60mAWAoHMirHZUrVdMsBQkyer9ReABo
         X9zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718891960; x=1719496760;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+xi4mZasi5vm4eg4cEoIT9vHFsfqAaLD6QdORB3MuHc=;
        b=ikXtaOrKW9iTdwca+MSRpL62xxCMaEQS1p27/JJyl7qM8K11EMQmu4m7WLfQB5nsah
         wixXKRiWxLsbqsm3Zq2IaJX0D3M1NY+NC2DTwqJvQpsUW5l9ui8C9aKpR9dXmopMazlX
         Q8BX2skW0/jO7QWlE2KWhmZ+mTA+sjRQWPIvoApLB2duTXAvFcDyHL118hFDg2aq8nEh
         fsif3/LL+OWglaKfTxYueUay6/bdD0HWDmA0R3GUc54QT8zmL6e6nyApcq3BiK5j7t9b
         bzSMhSR8jwmqNC8y/eUuZcFHN1EOE9lYbxSBdtiGg4Y7YF3AzyxzgAXXPu5ZBU+3/0oG
         8MVA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWbg0j3qckmlVlV+fW3BbPugO00NW72sBxK+HbuN+jd93iyWa6KY8VRuSlE6nZ9Y5uqje407YAHVt59Svz9M/bUthoqMuOjeA==
X-Gm-Message-State: AOJu0YwD+hgnCFv4awd1muVkrkjcMsXROWuBWMXg4XBa1s5BlxoSe2KV
	4OV7JSJdp8Aieo4c8eVHG48xsTawFjvxwapiiWIjq30q5dTk8fBO
X-Google-Smtp-Source: AGHT+IHWGSvVs3/eis+VVw4FNbY1OE440xLh+e3a9ZiunL2HcGTD+Qui5k/WCduRP6wKZ4SqpvhzLg==
X-Received: by 2002:a17:902:c195:b0:1f9:a79b:59fd with SMTP id d9443c01a7336-1f9abcf472amr6136925ad.22.1718891960272;
        Thu, 20 Jun 2024 06:59:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd8d:b0:2c7:dd7d:5edd with SMTP id
 98e67ed59e1d1-2c7dff07fbfls568000a91.2.-pod-prod-05-us; Thu, 20 Jun 2024
 06:59:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWyogOu9qEAvWTNRO9BzobJAOFVxgVIRDeFcViL5Br0q/BjXqbCIHPbUyW7rKfjP20JDHEtNRxuJEUelub7PXlByvABGIzeo1O+qw==
X-Received: by 2002:a17:90a:be10:b0:2c4:b0f0:8013 with SMTP id 98e67ed59e1d1-2c7b5b42405mr5258895a91.11.1718891959044;
        Thu, 20 Jun 2024 06:59:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718891959; cv=none;
        d=google.com; s=arc-20160816;
        b=S9XQl73TGpgZZ82QQpXDFbwj/fGiMoEQKtAt4WaMPqI+4i3BsAXHt/VQGuh/pJlESa
         Q94P0Rr04gry9KxokSiY9QlOZstXKESzMvqGjTHv7ekuMbSgdsl9nc1IRZmXfhsV/g+X
         DZ5Gdy7NOmUamZZp0Ys04HCg/Jj/7JCNfRwuQ5MsZIjOvcXDCSU+sQBq6sbsyzhQfhnr
         TA1r0DuQG05okexgZwMWxakoZBG0dAqWLGIoeHHedTPC7HgrgyDzrsRBduVgtHnrR3Rn
         myja3Xzrv2jKP7CYbVMWokBcOcow/zRusonYeo6YJ2aopQbSMZtjyEcxSyhqNbwv3ggW
         m1CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Sx+HfB3BR2YRmT+xxLQT+3Kz6S8G9rp0ct4rpiaXuzk=;
        fh=eUQW7IhWDHChH74ax7Qu+GWbgAXuHHxgFdOHk9U0EvY=;
        b=Kc9aRB4M3fcNsd8LZVH5vtAAamK8445kILxV8uw5mS+gOR/WWDuOp8rbwwRFcD4lqW
         jLhsUtGf6Kkkm4DDjmnNprq2vzBsa4wt6z8EMe5oDvT7PTEvVMNATiq0/AI/e+zOcGJk
         SMaAodQ5Nv0FI/BfwPpmIdLLxZStr7oFOshkFu79kWXMvP5jNPXKaceB30AtGgf6bNww
         G4mkU6C44xlOmbVz4ea5lSkqyeqUdBw4HCEmgmA9LOruQj0YGerPjIdbYzrtGoBTdbgu
         VXDbLhN/Bel3zG3/tZhb9eOXqm8/8s0rOmKEKzt5HWtyS1wlRzyHIghhnD95VtVeMSsY
         Xg5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=XOKXz9J4;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c7e476febfsi85332a91.0.2024.06.20.06.59.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 06:59:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KCcxjq025693;
	Thu, 20 Jun 2024 13:59:13 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvmfcr8eg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 13:59:13 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45KDxCiQ030476;
	Thu, 20 Jun 2024 13:59:12 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvmfcr8ed-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 13:59:12 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KD1dpH009433;
	Thu, 20 Jun 2024 13:59:11 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgn6b1s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 13:59:11 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45KDx5b110355036
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 20 Jun 2024 13:59:07 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A8FDA2004F;
	Thu, 20 Jun 2024 13:59:05 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4A2632004E;
	Thu, 20 Jun 2024 13:59:05 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu, 20 Jun 2024 13:59:05 +0000 (GMT)
Date: Thu, 20 Jun 2024 15:59:04 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>
Subject: Re: [PATCH v5 36/37] s390/kmsan: Implement the architecture-specific
 functions
Message-ID: <ZnQ1qPGClXw/rB4o@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
 <20240619154530.163232-37-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240619154530.163232-37-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 0sr2wn6JJ7mPm7i81bBoB7ypHtTLDaoS
X-Proofpoint-ORIG-GUID: mWcN6U0d707TXYiv4F0Sp_RI3phaZYEa
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_07,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 priorityscore=1501 malwarescore=0 adultscore=0 bulkscore=0 mlxlogscore=407
 mlxscore=0 suspectscore=0 spamscore=0 lowpriorityscore=0 impostorscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406200099
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=XOKXz9J4;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
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

On Wed, Jun 19, 2024 at 05:44:11PM +0200, Ilya Leoshkevich wrote:
> arch_kmsan_get_meta_or_null() finds the lowcore shadow by querying the
> prefix and calling kmsan_get_metadata() again.
> 
> kmsan_virt_addr_valid() delegates to virt_addr_valid().
> 
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/include/asm/kmsan.h | 59 +++++++++++++++++++++++++++++++++++
>  1 file changed, 59 insertions(+)
>  create mode 100644 arch/s390/include/asm/kmsan.h


Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZnQ1qPGClXw/rB4o%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
