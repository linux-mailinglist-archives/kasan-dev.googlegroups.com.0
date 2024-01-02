Return-Path: <kasan-dev+bncBCYL7PHBVABBBDGN2CWAMGQEKYV7CWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 20790821E48
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 16:06:54 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1d40aa361f1sf20658075ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 07:06:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704208012; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gz4HweT0xwKaEroNwIPpohCYolxbyST1YkBRXtA2HBMUgzrU96kZ1UxldAlfqjetme
         bXhRTb9w0lKVSfwzPyXuksa4iJFetZ1G3Y9bwKPCns3+7IUOJZgeSR+9/qWsnn9SYa/g
         7ibS4eOmR1FOWRRuTGCJ1OckQP1HD9CxhAXsbmnqUsPIYoLIaRI0wNgE9UMBJwhN+GpH
         zru19zJF6muenVordqUgdbwqav475O7Vt/yIy0VP51IeUUskYqEDqxQzC0Lj2Un/A9V/
         gcAnlgoZ0I2szMbAGjUdyit2c8N+/kYNvkTIsmvoVzHevdnuzngjx83GdlIwkL/1BH0T
         fzLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wAEfuZPvipyErMS+iwXH+rB0Gh8TBlNX13Vo14WZjAk=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=xcI0h4gzuPMmRVJwJ/N6psAjr4jGapuS7tCJFE6Q0S1fKn2qFOgIZ/d3vnDzZ7egym
         cau3igP86pqCJPY1Ac2FXJyXhvEDMxuDoFEoNo15HHLSmYqRCI1ohJh/OsUZ2MPuuu/H
         xyMqVpVeknGNAwRooHbJaJxXql73FaYn4tpug3OSWvbgOf9jBNqi1XdV0+NJlEIK28Sz
         pgeYY1f56WS76jeyadXrhyTgTEt0AC51LXafh4nVIB1NZSVbltJ65Y3CMj+DpW3XRxi8
         7l8D9fxOjh9X/Xx+/YE2Iv+vhuJVUMwcclRfKc/01yc/d5w78OrSzoSzitlz/SgXl+Ym
         7oMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="K8s/TXnn";
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704208012; x=1704812812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wAEfuZPvipyErMS+iwXH+rB0Gh8TBlNX13Vo14WZjAk=;
        b=jzpodcKdFI8Q29/MiZzpAZae0GNLpw4x1uOfhMYxgOnRb2Ra6KE5N0Wx2gdyuqdXXZ
         MwJx3N38uolgmtq6qY7t/bGdP5qWnZLzchiFjihJafkAv3cpfV2qRBJpvnzDOjvUml/E
         DF+3aPGNwSYyS3BZ9LOeqQtNBXX7hHxbWTDdsB9f76rHfBX3lwJ3jdDzndZDgeKzi770
         GdpBtAyXO39/rjzgRXTX4zYxh2LrVdTCWkRVEG851wRJxdufittPfC+O8c1A8/QGT1MU
         vrtJMrBgz76eOGroxiXAgpe0Dpv9TGkLX7g3aeZw2hrWs+HHP/7DU3zyk67dt4My92Xf
         nWfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704208012; x=1704812812;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wAEfuZPvipyErMS+iwXH+rB0Gh8TBlNX13Vo14WZjAk=;
        b=ohJnNoujxBX6pJDjP81awlM8db00To9qSGEYK3WR2h5YqeQYDDua0Zq8DjagZH2/dO
         RHrr6JjdSc7oa4lFqCd8S3HGCg+xzIMd9vcuksExWhXBf0yCkz0BtyaT3YIKxwTN1Hg8
         1sasDYJOwj9XlKcCIt4v0ghw1gJV1S5C3GQib9yHbThHnTnC79fx++QfL+gzg2fLOkcO
         PTAvYFP1bQO0xaaxOyL0FWzbZVytxBNZsrnCzDCHaXyntQuWJ9ydSeoYPrIHB6jBqIer
         VXvZp7nPxE88B6n42sNow+2Jf0RSZkiuxSkdauHoTHn3nbL31piaYqn/XbSeZRFfr+6y
         wHYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy78PV4/ncSr0S1fn+Zf4L8QHIN05w2YyRj4z9/C+vWnMs2s5GJ
	YTpZ90jHef9qD/SRtjuNAmk=
X-Google-Smtp-Source: AGHT+IEXoOIyPxSjl5guAE4bGO3s60DFTkPwPzJyX9/3o3Huvgyt68NTETO9sOaCW/QqowhytIhaUQ==
X-Received: by 2002:a17:902:cf52:b0:1d4:3cf7:ef28 with SMTP id e18-20020a170902cf5200b001d43cf7ef28mr946529plg.9.1704208012626;
        Tue, 02 Jan 2024 07:06:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7c8a:b0:1d4:cad5:be9 with SMTP id
 y10-20020a1709027c8a00b001d4cad50be9ls181474pll.1.-pod-prod-05-us; Tue, 02
 Jan 2024 07:06:51 -0800 (PST)
X-Received: by 2002:a17:903:2c9:b0:1d4:61da:1384 with SMTP id s9-20020a17090302c900b001d461da1384mr7927154plk.106.1704208010820;
        Tue, 02 Jan 2024 07:06:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704208010; cv=none;
        d=google.com; s=arc-20160816;
        b=0s80u+CZsWL9GfcP7D4egd/nWBj6+RsOc1a7F4UF/dRutdwEH+okVOQB2fSofU0Jxu
         mey0DWuLN9pUUeAp0JjUEs9AMk/hbKQfXrP03Ikk+H+fAcDcGOEHIJu9iZbTXF4ouZ65
         g+UaWuzPO+qYhx+MsmdX80oK/ioC9/+g4/4/+MbUrSfnexSyje9pzSsw68huBxcL7WJu
         20mjHLdgQA+EMHCCH7+LrM6B5KwlF8cVJZqSFTe7o9fPookumoKYh/IXGCkQmDxVcMsH
         Q/u2GaQV2iQ5Zxs0jBtNqOvXQUc0Pr886m96Eudpn9sOPWRLtp7DNXOzrvLpiws+/+E3
         5Ahg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Oonp123cOdkP40iNRTSGS2eTt70BPLYr/b5oy9HIOrE=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=OlktgihJA4PJNKm3V5TzU0eLZrlrRg5HKuP/VpddtZPQ7Zr5Nv3SDEcb+NSmmptNcg
         aows/LhiyiwEsn5eeDNG/Z19ezS1RxwwcWVncTx5e7brZDooFVy1FqA22XiBlkdY6RZV
         T9sb1f6NGOiISCUfGWclTzVSuG+dXGCTa0GkI411CaHBoWEP/1W2Nc/o0Tm1IT5MoEfN
         Z03yFQ6GcO/1zU/j1M8lUqFYY+sq3vgLbnhQ8/NI/TmuxzjkKJA6M/vl2pt5Euzr/L4T
         mtwf8tTK9I/8669YKPieYOXzYRM2VvSpJxiqDPxkbTDt0OnSGC+Je/EvtmR9OhT3KCPt
         EQSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="K8s/TXnn";
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id bc5-20020a170902930500b001d4b03b7914si249843plb.2.2024.01.02.07.06.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 07:06:50 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402EI2Yt031896;
	Tue, 2 Jan 2024 15:06:47 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcm4k9a60-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:06:46 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402ETn6Y004810;
	Tue, 2 Jan 2024 15:06:46 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcm4k9a5g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:06:46 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402DoQfs017830;
	Tue, 2 Jan 2024 15:06:45 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3vawwynmw4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:06:45 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402F6g4R22020754
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 15:06:42 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4D94B20040;
	Tue,  2 Jan 2024 15:06:42 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EA9552004D;
	Tue,  2 Jan 2024 15:06:40 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 15:06:40 +0000 (GMT)
Date: Tue, 2 Jan 2024 16:06:39 +0100
From: Heiko Carstens <hca@linux.ibm.com>
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
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
Subject: Re: [PATCH v3 30/34] s390/traps: Unpoison the
 kernel_stack_overflow()'s pt_regs
Message-ID: <20240102150639.6306-H-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-31-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-31-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: leYrbA6vtAty3KAE9ah14tjkk5Bn0Uhc
X-Proofpoint-ORIG-GUID: utJWxtGOYHGAv9Kk1hnF_c8f7r1ax0vb
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 mlxlogscore=933 bulkscore=0 phishscore=0 adultscore=0 priorityscore=1501
 mlxscore=0 suspectscore=0 lowpriorityscore=0 malwarescore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020115
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="K8s/TXnn";       spf=pass
 (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=REJECT
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

On Thu, Dec 14, 2023 at 12:24:50AM +0100, Ilya Leoshkevich wrote:
> This is normally done by the generic entry code, but the
> kernel_stack_overflow() flow bypasses it.
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/kernel/traps.c | 6 ++++++
>  1 file changed, 6 insertions(+)

Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102150639.6306-H-hca%40linux.ibm.com.
