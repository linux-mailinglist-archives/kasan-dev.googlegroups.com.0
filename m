Return-Path: <kasan-dev+bncBCYL7PHBVABBBNGO2CWAMGQEXGUQG7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id AC013821E5B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 16:09:41 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-3bbc1de001dsf6352361b6e.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 07:09:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704208180; cv=pass;
        d=google.com; s=arc-20160816;
        b=gCwEupt/N3rYPcbgfnHfxf/1HVqDy/P9DOqAxQDHd13Oah2xQwOxc4KGdpMfSTR2F+
         sihvOHJfE+jr9S5WVZK0jLWCESypi/84v+fwyHWk4magUG7ktm3E0n0wcu+Y3gZ+jLgt
         sp9Hdt3CoRda/fllZVnSdp6c67MKufDHqDDoqUoVGHH8wswmX5/T8svojt9BdWvVl0D9
         qA+lKRY+NZy7SGd2op07Kanu3hA90AYo/RmO/axmrLIL+i9HnuzXiupkzLgezBTukneU
         wyXspWrKU/z2Qx5cLy6VL6zVRvPFX+YgWhFxdUU7IlxSpdERgK4r141PGcXWUDQKfF2i
         EqkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jZ/0zXNgbDBU+I/dMsaBH2sOnPih7LxfHNpMbQnOpZ4=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=ntSeUfsd3bhKoW+42Ccz/g2ne9DMkuwfI+17UpO+qFlszUluHe3RQEgunQISpDF0DZ
         BBhTrXc+ZrtO7j8ajQta7SRNbuSj3Js1s8cuI6lj0Ket8Cc0c3L2b8GWBMIlwBlIwvxj
         Y/F4DI4fC/E/FKqmdziYsTJ2tJYjQgORmZ2MPDG7E9rEbm+P+V0JNqdHtXXHALBestN+
         ToiNi7r4LX+ts0dNYZcSJS5I0p2vf8m6m29N66SXdlqUo0v7Va5ZqrnFITqJDKh4OTuk
         QiN9lrtfT/z7M+bXlqOXKkxwQ4xG0Zs5JdbgykgwiHo41hS+xmsLBhLaeU91XEYI9TFm
         NdAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=svD4su6l;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704208180; x=1704812980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jZ/0zXNgbDBU+I/dMsaBH2sOnPih7LxfHNpMbQnOpZ4=;
        b=GpYSEQmWZaMetSRcec/OxrNeeVwY7tX/B2Lx9QEEjHxhNd9otHFAZcD9kEfn8Oa7QY
         NKqlXHZ66/1Xa7OWUJAB4Kq9BSJ8QvKaR7QNGz8hQc8QH3/5U+RKsf/ZJOWS9+MKMYYK
         khOfQarrPjdMa3d2AdXGAqSzEYkXyPCpWICaREeoEUswl3QS5LHP1FzT5CKJeYJd+mOb
         SLL9toPydw0SS+Hv71ZBlc6+dUlF9gJBRFj7Jd/MSh6gnKnstiDeIJYtzHSBBt+18jXk
         bfFAyP3OkpfQ+wXNX+7oPtNn/ZwON/4UinDb62aLtLpighF8xDc8D0xW3dwNJjIoR9rW
         kuzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704208180; x=1704812980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jZ/0zXNgbDBU+I/dMsaBH2sOnPih7LxfHNpMbQnOpZ4=;
        b=obzhI6hXgQxr0zKlLb57qmlEs10rIEMPhS5+NELzGj13b2myGeyzD+MwcuWo4rfz3s
         dbvDjzzrb6GB5ZVUpeqRSXwna6deqSmKBdteagbljXOnoVE2bUyEqNd2NfDqUDG7EeL9
         L3LiXazoPyoq+kuMVCwH1MjmCb9+0hCfSx2cyslkYaO/ZHRwhzCQLbqTGOQkY5vEx9cn
         nF+FpQJnDawHVPkkDRoHYtivkqyjFfe5ehVUHJr2fRUkKqvrGQZVFfeFrV4T6hmmGCkG
         QNX/emWVnPX8CMqmsKtdRkddO41q51XyK4vFkBILucMFHAuFkqV3OeOIAd/RXlHWgFso
         FUIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxX3oMFnYBFzH9XPJWBv4dUEBBHoDriVQLFk2gg1wmJqzmbMkA3
	o1morV611+bsTf9K5Q1YzK8=
X-Google-Smtp-Source: AGHT+IHLkq4QTW9R0GRRSGjrlsaj4GAVsUwe/WgHXsJ8PXXdc9vL8iKWCS7/WPORiv1yPVVNLCs+5A==
X-Received: by 2002:a05:6870:8dc8:b0:204:45d7:2e86 with SMTP id lq8-20020a0568708dc800b0020445d72e86mr23132420oab.110.1704208180367;
        Tue, 02 Jan 2024 07:09:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d894:b0:204:77e:d2ad with SMTP id
 oe20-20020a056870d89400b00204077ed2adls18970oac.2.-pod-prod-07-us; Tue, 02
 Jan 2024 07:09:39 -0800 (PST)
X-Received: by 2002:a05:6870:c114:b0:203:ff1c:5525 with SMTP id f20-20020a056870c11400b00203ff1c5525mr21237503oad.67.1704208179606;
        Tue, 02 Jan 2024 07:09:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704208179; cv=none;
        d=google.com; s=arc-20160816;
        b=0M9Yr4yavs+8UQFexSEueUTmKqsaFdbirlVi8IjMmwd4eXI+eEzLeaxzEMwTbyHK9y
         ZqKocKu7J/ajLDJ0etvMdgJJyR/+aRcXEnVBor+c1gneVmxKBGXX2iMHX0MD2S82fa5b
         7sLWMUuBaWbAZU0LhhV239flAJxF9+InNlcedodazQNbO105eWftRTJ/9x2Y2Y36Db+J
         1uAgmmcBnMgobSSTkBTtBfWKtAUQ0rVOxA3dYlqJKx/Z2cQgQTlpQ6RWr9Frg6CCHgMY
         NKydkHyYh0sIBqxArbRZ0MP/P6o4iIohhZ8r2TajKW/Sz+tDK4ZTIsSz3bsKqGcAUhlx
         qJ0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Z16gIvE6o/oyg7pKiGRgBezqdCKIKpf4AGEXuLsxRFw=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=CUBvw/QYywNaPmCCxCwcDJKGqE1E4+HUcWylvgq9719UsMnMArYhANE28uGv4U96Yu
         rEN/RadJ9KMZuxewbpAVBjRz+hogR39sAra7Lgd4t51rLz4+0fQUcHhCkrwBBbykdirH
         2m0IZ8/iJvUxjbazAtyQIbTeFG8IYeWr87O0QG7GnPB4t/iae/GIDNDz6NQ9co0qBPaQ
         eR15LGjBDNqIoENXqTAcv6FJSE1sY/2ZVDzcOfhgxtntIfBOWU6wsj/MLtSqMpJsc1lp
         HqH3XxIIzTECrzST+8Wc2DcTLhlrrANbNqQUB41Vn9dU1SpEXJkRNizHnRQIe/13cREZ
         vH1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=svD4su6l;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ws22-20020a056871ab1600b0020422fc069bsi2125045oab.5.2024.01.02.07.09.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 07:09:39 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402CRVvJ007618;
	Tue, 2 Jan 2024 15:09:35 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcjghkfsn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:09:34 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402EKo8H022188;
	Tue, 2 Jan 2024 15:09:34 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcjghkfs7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:09:34 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402Ds1wG017834;
	Tue, 2 Jan 2024 15:09:32 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3vawwynnak-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:09:32 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402F9TLH19726960
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 15:09:29 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5DA132004E;
	Tue,  2 Jan 2024 15:09:29 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1E7A720040;
	Tue,  2 Jan 2024 15:09:28 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 15:09:28 +0000 (GMT)
Date: Tue, 2 Jan 2024 16:09:26 +0100
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
Subject: Re: [PATCH v3 32/34] s390/unwind: Disable KMSAN checks
Message-ID: <20240102150926.6306-I-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-33-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-33-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: exHf4oBJB85XIi_IDJ_Zx4a73A6HiVoO
X-Proofpoint-ORIG-GUID: 2sCBYVkslnYpbOQdpV7tqP0ZF1S161uX
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0
 mlxlogscore=425 lowpriorityscore=0 spamscore=0 mlxscore=0 impostorscore=0
 phishscore=0 adultscore=0 clxscore=1015 suspectscore=0 bulkscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020116
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=svD4su6l;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, Dec 14, 2023 at 12:24:52AM +0100, Ilya Leoshkevich wrote:
> The unwind code can read uninitialized frames. Furthermore, even in
> the good case, KMSAN does not emit shadow for backchains. Therefore
> disable it for the unwinding functions.
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/kernel/unwind_bc.c | 4 ++++
>  1 file changed, 4 insertions(+)

Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102150926.6306-I-hca%40linux.ibm.com.
