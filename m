Return-Path: <kasan-dev+bncBCM3H26GVIOBBZPB2CZQMGQEBTF5SUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id E816591064F
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 15:38:47 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2c7430b3c4bsf1082609a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 06:38:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718890726; cv=pass;
        d=google.com; s=arc-20160816;
        b=xIBHau27Tl0YvKiHTL4x6A1LQuJJ72d2upyVdpANr29pzARnj7eMvg/qOQdPbxmlt1
         48xOoHrTP2JOpjhyRJsF1if/E/KgYtadlZjMd31kescfV9b8dLjpZ3KuUPTYL2WxKzui
         6/dnTE4Q2J/Sx/2ptakUNheI6XWeIU5IE3kPLEteK4gdn4GZps7CCfeHAyQqN6KLRshy
         kDu3qqYKUz6aTRhBokfL8ozYq6wAZ3CNw/ZpImnauLsXd+dxLRbamBwn4fgimcpFIiy3
         jvA3xLL8LScuko4v9QDtWZzwD1tWFTEwowLW+7DMqk6bgYGCYlccxcC+xLISAD8zFwPu
         udaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=QUo06TU7ZEopshk8rkZetPu1vUIEBAFDaFAdWFSRuXg=;
        fh=D7EWoXMCBJr5FGdVun0Yv9vUzuSqkzJApGWrFThzbVA=;
        b=RZqbUl83vkeDoxbwbTL06vvwM5gErQgCuX0lg/b1dWZFn55r2dy7cE57W46R1csDzJ
         OJ241WxTq+VtMYh3zvYu2K2w3IPQY1kzHKOg0CUtEzBwZ/nmvMxbagYj2TXUZgcctgdQ
         DglS82HJl+royi3UBAl4hqWNkJy0gSt+loOVMs4US3mqWAOYEOwrsrpoEND3oLFFiio1
         tg0+FCERM+JADA9OmNg5aoLH2jAs41ohksgVYSYtlyZkbgibtaCEyut9u0uKHF9gfZm/
         E8BqecWxx5DNSNWsACIo25C3sKxDPeQRBiLJzZDn/gqzlzPrqc4dzRoI0N9MeneYaQ7U
         CTeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DVj2yxKJ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718890726; x=1719495526; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QUo06TU7ZEopshk8rkZetPu1vUIEBAFDaFAdWFSRuXg=;
        b=RG56kNxRXHqwXDS3ARrrpoiZ9slgu8QHABhACwT8nCLF7O3YNwx8C1n1luSJdVeHtC
         PhSC4PM0pxItUr9kwAUam3zUwWUBYALZdRiq0rH6Iw3uqU8UYm6advc824aZvCzeMhSn
         SvhkTNegNAtzMz717brFxRKb34NXadiRRFpkYLnd1twCfWvb10GlkaVmU+W4dUG09SFT
         7E1ZyQIrgs/N9rZw7o6c2px8XHjp1V62vn286zwNlnahG3txOmUbhfmH3EbfZeaIEong
         8NCYaAeIOHIzJvle/PQOSSoKmY3LIJ+3Y9mUDwTlAHs/jjmhwpgF5wSqNuQzjG/izFWZ
         Qb7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718890726; x=1719495526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QUo06TU7ZEopshk8rkZetPu1vUIEBAFDaFAdWFSRuXg=;
        b=t8qVxLDYUFwxFLm5QsTa44VTQGtNu7nNZiKzQPOMYyQrB03CE1N5wCmXGQ/qfOsoSR
         3TNd0PKJKe4tHlBGCJ4EyzSkmkcqH5uTZyKZ4ElCqfXZ78DRT4nwPM1gl4gVkwAiZTRx
         j1NnXt4ywLfuJ6y/WU7QqzXLg8hd8esPSxH187O1wNMy37r0KuCIep0br1bXxrmtJJvL
         UEkIWW8HcEgsSWG18dSWkplMqeQCq18/0czUTw+Z9AI2tYYNBbVOxyx03XfLqThzrdq+
         LxrUMJSoSrMYA7Kf34fFwDMfzzCdJNt6y0+tOQyfmO9TzY1gK9ZdlJHkgnsjOjjTI7R/
         FvfA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0uUMGGXsJ4KW+0//HSCn+RfZRSKApG6+UwAcbsLhJOvMu3cedoVkvqdiQNf3VxzTERJoKslC7nGdVWizTCT3XWBNKfj3JCA==
X-Gm-Message-State: AOJu0YxWHw2UJ3p+erXDQvnq47KrdpebfOBOH7A1BSatyN+MU/k8RK0s
	MehsC9I85r67YvizbhtZFKW/utEdib+hUNCN2vO5GCMb05U1mAHC
X-Google-Smtp-Source: AGHT+IFtqS3Aer47kp487SGTXHArdJMn9lt3lgWDmQJLbApMkJYQlo09YVlqm4ofDfDbp90sAX8EXQ==
X-Received: by 2002:a17:90b:4d8a:b0:2c8:87e:c4cf with SMTP id 98e67ed59e1d1-2c8087ec557mr479458a91.4.1718890726049;
        Thu, 20 Jun 2024 06:38:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c52:b0:2c7:c37:2720 with SMTP id
 98e67ed59e1d1-2c7dff00e74ls576936a91.2.-pod-prod-03-us; Thu, 20 Jun 2024
 06:38:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWjdnoawnOOz1w1+16Is0INtepN24fyITMsdBAi+cONd36XRw1xlDOljAQm1txRAYoQJquHVWIVpud7gOQMbneBhduHQ+eeM1r0Kg==
X-Received: by 2002:a17:90a:d314:b0:2c4:b32f:4fd2 with SMTP id 98e67ed59e1d1-2c7b5d00ab5mr5176319a91.29.1718890724617;
        Thu, 20 Jun 2024 06:38:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718890724; cv=none;
        d=google.com; s=arc-20160816;
        b=chxAuKbbwWuYM3KEx+IHzFphxzsWVOqF5ciY2FCrwGMjioDHkODL9Kq9scAw5IN2Ky
         k7jbNfT0oRsi4mYHPMxlfBtWBUZotwZ9A+Svdp1doYPds+3WfpA5o+a0mHMe/8ZYFsKv
         kxNcMFeacgJHFzTIkLOBLl/RN/uGHcnYmUa0k2oCCNUAY+Z/j/YcFn7IhzlzEmvAyO76
         F4XiG5kpo71LGRIKHhHDc3eP0GHs4hb0klp9ywlg5SM95Q14csBJC569DSNudwCfw0gu
         hsnPPILU4wy+YSuLN/cZKSDML61rWLAdg+cXviVwMCt9m7+tXJumdBUjw8nV4LKGgYQU
         GQdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=YUbNUxVRxVzSfRB8DznG+AI9YazUwyusPtVlI9Nb7aM=;
        fh=x1xgfdIdQHN1oQ/MHfiTcB4Oij7M1u7c86rxbgZpnOo=;
        b=H4opUCWxcK9ncOqr1x2ssrLGCgq5OitLace5X/O6/x83LKuoEkCpXeldalGaDC5ZGR
         e21D2rpHxE0ssRCKayjlqG0FRVBsgPTjKP3d2znmQbTBSCFc6bJ2KOHSxyIDAy9FumtW
         TWs/ZS/1OI7WL+fndc5x5e21eDOIGAxZjIPeOtDMHG2mhJPT04ivACpEvC+otjuzVYNM
         MsY3a/ykRPEYG0k+Xgt27xT6kJTHlUZOPS2pBdm1kkKQFao73R4zgY3KOJQYp00XtPi0
         HiadZTz6fC+EKcVJIunM1aTPd+pZBylwPTchwjpu8vK99dmpHrZiqFbJnDOm7ITd3bHp
         Fw3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DVj2yxKJ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c806323f81si21508a91.1.2024.06.20.06.38.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 06:38:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KDXb8H018582;
	Thu, 20 Jun 2024 13:38:40 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvndp80aw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 13:38:39 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45KDYo37020397;
	Thu, 20 Jun 2024 13:38:39 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvndp80at-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 13:38:39 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KCIJjB023874;
	Thu, 20 Jun 2024 13:38:38 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysp9qphf2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 13:38:38 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45KDcWRJ18874846
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 20 Jun 2024 13:38:34 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4852320043;
	Thu, 20 Jun 2024 13:38:32 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EB7A420040;
	Thu, 20 Jun 2024 13:38:31 +0000 (GMT)
Received: from [9.155.200.166] (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 20 Jun 2024 13:38:31 +0000 (GMT)
Message-ID: <f6ab5d6e0aa90ad85e239a2da9252930ca9a70c3.camel@linux.ibm.com>
Subject: Re: [PATCH v5 36/37] s390/kmsan: Implement the
 architecture-specific functions
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>,
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
Date: Thu, 20 Jun 2024 15:38:31 +0200
In-Reply-To: <ZnP1dwNycehZyjkQ@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
	 <20240619154530.163232-37-iii@linux.ibm.com>
	 <ZnP1dwNycehZyjkQ@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.50.4 (3.50.4-1.fc39)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: EoXF46C30_1HJeuiJvzTvJ3K5p2rf5em
X-Proofpoint-ORIG-GUID: bqmJR33qqTSFJQTMaJPsqaDg4i4nBhCe
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_07,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 clxscore=1015
 bulkscore=0 mlxscore=0 suspectscore=0 malwarescore=0 phishscore=0
 mlxlogscore=720 spamscore=0 adultscore=0 lowpriorityscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406200096
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=DVj2yxKJ;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, 2024-06-20 at 11:25 +0200, Alexander Gordeev wrote:
> On Wed, Jun 19, 2024 at 05:44:11PM +0200, Ilya Leoshkevich wrote:
>=20
> Hi Ilya,
>=20
> > +static inline bool is_lowcore_addr(void *addr)
> > +{
> > +	return addr >=3D (void *)&S390_lowcore &&
> > +	=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 addr < (void *)(&S390_lowcore + =
1);
> > +}
> > +
> > +static inline void *arch_kmsan_get_meta_or_null(void *addr, bool
> > is_origin)
> > +{
> > +	if (is_lowcore_addr(addr)) {
> > +		/*
> > +		 * Different lowcores accessed via S390_lowcore
> > are described
> > +		 * by the same struct page. Resolve the prefix
> > manually in
> > +		 * order to get a distinct struct page.
> > +		 */
>=20
> > +		addr +=3D (void
> > *)lowcore_ptr[raw_smp_processor_id()] -
> > +			(void *)&S390_lowcore;
>=20
> If I am not mistaken neither raw_smp_processor_id() itself, nor
> lowcore_ptr[raw_smp_processor_id()] are atomic. Should the preemption
> be disabled while the addr is calculated?
>=20
> But then the question arises - how meaningful the returned value is?
> AFAICT kmsan_get_metadata() is called from a preemptable context.
> So if the CPU is changed - how useful the previous CPU lowcore meta
> is?

This code path will only be triggered by instrumented code that
accesses lowcore. That code is supposed to disable preemption;
if it didn't, it's a bug in that code and it should be fixed there.

>=20
> Is it a memory block that needs to be ignored instead?
>=20
> > +		if (WARN_ON_ONCE(is_lowcore_addr(addr)))
> > +			return NULL;
>=20
> lowcore_ptr[] pointing into S390_lowcore is rather a bug.

Right, but AFAIK BUG() calls are discouraged. I guess in a debug tool
the rules are more relaxed, but we can recover from this condition here
easily, that's why I still went for WARN_ON_ONCE().

> > +		return kmsan_get_metadata(addr, is_origin);
> > +	}
> > +	return NULL;
> > +}
>=20
> Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f6ab5d6e0aa90ad85e239a2da9252930ca9a70c3.camel%40linux.ibm.com.
