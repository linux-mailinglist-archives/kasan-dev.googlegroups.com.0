Return-Path: <kasan-dev+bncBCM3H26GVIOBBHET4SVQMGQEGHMLKZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F6458107A8
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 02:32:14 +0100 (CET)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1ef4f8d294esf9763457fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 17:32:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702431132; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fmv8SScmNwYz1qT91FdV3/CMqIre8T8qUTGln58stvBPP8LxBWED7BGtR59Or6GO2D
         bkk5g2HWar+LWwRYqiL2ujR6Kk2X9ZW8DWgh74Xipd+rPYzdIstrQjelUX4Kl6MGzTGp
         LHpPdCN9wZ4y78tuLfbS4JQchdKzq6ildwH7gke1Tf4biFiRr5UCsGvJyqJ0sGVFHlz6
         27qHyjEh/f+ogZ0AxD5CSD9ByMw0CfELLrda21Ur9qIgfD65/E2Dq7nTbo/lJdk84pnH
         XisgjOtpLh+ksvD+0IiSTNdYUOn2wA1wYpWrzugH+wtG9RFgAao/uTE6bC2jSjsL1CLo
         HGnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=BA5vTsL8gMs1KO8ms1HbE3/4IgkXjqug3Vub27cr0BQ=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=A7NEK3NxLXX45VBGM2/8xpwGbddxz4gQKDVQ9k/cXTZOnWf0Jvd2U0IL6q1Tktrmt9
         HZt1JI41Pa3mXdN22Lv9Nf8Nnx41MhKnN2h+n3sJKnyVeMeCq6NUSALusPpQXUcSMiH6
         758YzfhyjAaJb+RFf8IjbZeRu5kkqtuKXrfYO4KRCMshkYH4+B4lTzvmHKv0SJ0kH/9I
         qJloAKf3qGGcxqDeBrDL1xIHgY1LrNcjLlJZQPVw9G6aSht9I9Y188ej+XIR6OvyqLix
         n+VaF+YKTMVS2qs1HUKobzOkWCp2mykuLXUTN9ubdZIuqbFVCPMEwC73JI4iOmej11iS
         PXkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Fnt0wkfy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702431132; x=1703035932; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BA5vTsL8gMs1KO8ms1HbE3/4IgkXjqug3Vub27cr0BQ=;
        b=nr/vbPpn6yFZYwsANVY1v/x+TL5xL8H3cTcY2qDbekq11Lj2SALdQgGi2ZM4L9RAu7
         ftfreiC3aCZDutR73W4dQACNlvOYKGIBt+xrB/MtOGbyonYzbp+AogVGj60FtPLIRspm
         bztMDwYHG1T65rcpPtc8C7XG9DztTNY4hC/mvfKFfXWbdRNRLUUcWOF4StuemqFIYiCn
         Jb2/dOXk8Qn4WWaxOQUFU9MiwDoBTyeRPn+rEhO1XI6jFnZ3S0YnHsiEq0LIfCKYbkQG
         K1fLs85aoZAOU5bgGa9dFtzvKO674xRBz591YRwUOz4sX5JR++GQyTS4w4ySWn8XFTj/
         xHNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702431132; x=1703035932;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=BA5vTsL8gMs1KO8ms1HbE3/4IgkXjqug3Vub27cr0BQ=;
        b=h49dRworrKHa9LmR0ym6bUnTqcrV9VEpB0tE1bady/JU1MAJPUVYrAOSXWbhkAw6On
         B5z1a+t7XUngiVm6w0acOi9j3VyAs+E+WQet48n6PRM+IueU+RokYTaXpU27aE4KgJQM
         MK2Z/UWCq3XOSoSDtiWxVEM7T/GbTuM2z/kJuTkSbt6a73blNUqxBVQOxiFUIU1PaiIK
         R2xxNMnkJZ9xzzDYkqB9CKZAsNgoUU8zRItYBgHt4n6C4tfuJNmqloW2nl7Xcdwco7zF
         VMq8jWsjSXpZmvluBbBodzEGW1yhxBc805BEB6BqNB39pX5RITQ2EVaXpS+6fkjTdATS
         dAmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzC1gwyV5tZC7iL5WMBSwe8ruqJFtZ61PnqZbqxOBD5K+zOMY3b
	5RFfldwSjf3qXv/tC/cS5Is=
X-Google-Smtp-Source: AGHT+IESu2E67yQckBsFr4SAWigkeg0GStQ01/a86P9IcTJk8cryeobL6+b+MKuu4qOUvKbRhqc7DA==
X-Received: by 2002:a05:6871:418f:b0:1fa:dba8:dcef with SMTP id lc15-20020a056871418f00b001fadba8dcefmr7714627oab.29.1702431132729;
        Tue, 12 Dec 2023 17:32:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:be9a:b0:1fb:38af:b153 with SMTP id
 nx26-20020a056870be9a00b001fb38afb153ls1403178oab.0.-pod-prod-02-us; Tue, 12
 Dec 2023 17:32:12 -0800 (PST)
X-Received: by 2002:a05:6808:3090:b0:3b8:8247:71d with SMTP id bl16-20020a056808309000b003b88247071dmr7970821oib.18.1702431131927;
        Tue, 12 Dec 2023 17:32:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702431131; cv=none;
        d=google.com; s=arc-20160816;
        b=rUNA1+BDh0ATumFmWZlbLhUPB+EDpEgOO9xVE6Mc2uK4AiJp77hP5pXR3Rw4I30riv
         Ug65YkrWwWpNl9THv7VMXkb7+26pYB3LxZsN7nx57ueP/ICq0rmT0UP9rDv8kQ/0Ad+0
         pdp4tirmJLtlRYZZTsgALZUPxQKk54a7K9AZ4t+0KQCZQKCnGdTaAv9/Z7RXnCIhC7sC
         4c+ieVQ9sHyNPgJgJnQGgR3FGuy1hhgF9e6TAdKb77UMfs2roq20Sq0H2We6VgJElQ0q
         gQvAujhw+hH4sYb//Q0GpjCOBbWDo412tlyxLqH6kK3UAOycmNqCtCpjbYmO1DMr5K/q
         Hrnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=KMCbxYyj6q/VXSfTdo3NzbZtbBOQtb6Yz6XeblWpLIY=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=c9/5cuRZpATJNzoRXErQsuNmVIj/kHyU0PfMWBwdSC7BCpNz7su/rJDioeGngYUvuI
         aMhkHTJOFncKdHw71WBv6LMlQ72Y1bnCxVJr3Cd8kPDDkDnDigrEUG9UkwPXBT77hRdG
         81p0mNF8qpuHfyCv15+8IFEPk4dKyB1Ll7UrQUbBgK0ccjSdWlAIxvocJvh4QGEGrMd9
         ObJw3wqzJTyk4hs2q4HzgrCu87w0zYT/TtTpag1DZtgNtyYkmVzdwxhV2+AOJlql+I+y
         d5WgP2Ii+zIQjv6gpDa3PPWnz7jZO2WjAuzwa5R0m768reDa8oZF/tIoljDx8ZFVqT+q
         fbHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Fnt0wkfy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id sk6-20020a17090b2dc600b0028ad7b9a520si129233pjb.1.2023.12.12.17.32.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Dec 2023 17:32:11 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BD0pBG0012640;
	Wed, 13 Dec 2023 01:32:06 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uy2361d6q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 01:32:06 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BD0pIkx013397;
	Wed, 13 Dec 2023 01:32:05 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uy2361d65-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 01:32:05 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BD1SnXL005066;
	Wed, 13 Dec 2023 01:32:04 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4skd26c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 01:32:04 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BD1W1q015074038
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 01:32:01 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 75E0220043;
	Wed, 13 Dec 2023 01:32:01 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2758620040;
	Wed, 13 Dec 2023 01:32:00 +0000 (GMT)
Received: from [9.171.70.156] (unknown [9.171.70.156])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 01:32:00 +0000 (GMT)
Message-ID: <626be6deb066627a77470bf80bb76c27222a5e3e.camel@linux.ibm.com>
Subject: Re: [PATCH v2 13/33] kmsan: Introduce memset_no_sanitize_memory()
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
Date: Wed, 13 Dec 2023 02:31:59 +0100
In-Reply-To: <CAG_fn=UbJ+z8Gmfjodu-jBQz75HApXADw8Abj38BCLHmY_ZW9w@mail.gmail.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
	 <20231121220155.1217090-14-iii@linux.ibm.com>
	 <CAG_fn=Vaj3hTRAMxUwofpSMPhFBOizDOWR_An-V9qLNQv-suYw@mail.gmail.com>
	 <69e7bc8e8c8a38c429a793e991e0509cb97a53e1.camel@linux.ibm.com>
	 <CAG_fn=UbJ+z8Gmfjodu-jBQz75HApXADw8Abj38BCLHmY_ZW9w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: uqRL-_gQFksj6cXf_VfQabVl2MwU5Zww
X-Proofpoint-ORIG-GUID: MvszSTT3P12rTHdpiLBCqdmC1cvhFx41
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-12_14,2023-12-12_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=802
 malwarescore=0 spamscore=0 clxscore=1015 impostorscore=0 suspectscore=0
 phishscore=0 adultscore=0 lowpriorityscore=0 mlxscore=0 priorityscore=1501
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130009
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Fnt0wkfy;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender)
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

On Fri, 2023-12-08 at 16:25 +0100, Alexander Potapenko wrote:
> > A problem with __memset() is that, at least for me, it always ends
> > up being a call. There is a use case where we need to write only 1
> > byte, so I thought that introducing a call there (when compiling
> > without KMSAN) would be unacceptable.
> 
> Wonder what happens with that use case if we e.g. build with fortify-
> source.
> Calling memset() for a single byte might be indicating the code is
> not hot.

The original code has a simple assignment. Here is the relevant diff:

        if (s->flags & __OBJECT_POISON) {
-               memset(p, POISON_FREE, poison_size - 1);
-               p[poison_size - 1] = POISON_END;
+               memset_no_sanitize_memory(p, POISON_FREE, poison_size -
1);
+               memset_no_sanitize_memory(p + poison_size - 1,
POISON_END, 1);
        }

[...]


> As stated above, I don't think this is more or less working as
> intended.
> If we really want the ability to inline __memset(), we could
> transform
> it into memset() in non-sanitizer builds, but perhaps having a call
> is
> also acceptable?

Thanks for the detailed explanation and analysis. I will post
a version with a __memset() and let the slab maintainers decide if
the additional overhead is acceptable.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/626be6deb066627a77470bf80bb76c27222a5e3e.camel%40linux.ibm.com.
