Return-Path: <kasan-dev+bncBCVZXJXP4MDBBZUJS7AQMGQEPZV622A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C061AB8432
	for <lists+kasan-dev@lfdr.de>; Thu, 15 May 2025 12:41:44 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b26e73d375asf41717a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 May 2025 03:41:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747305703; cv=pass;
        d=google.com; s=arc-20240605;
        b=V3tMhviU0nP8epFgRag6D0I4sfU8DY3VYnZpI5fYLAOXZncWGWM8u+3hq5P9z3xIsh
         oXwrYboGnDnXGPyPgJJ9EpD5zitJ4a1sg9Cwab0iwuemTdtBO0GTYsHIHITlmLFF1QJa
         JqGXv19TvdVwkCzxJHLusxUoKGiDa+pI/s4pc+tePT6Xh2NmQnGO7ftGUcvWeI+i4rZI
         XFIQOdPNs7FPTBGwHydOBjSv62DMmnjb0dULiRGR4qe1AojZs5tsYpeIogXThv+P51+b
         xJsINuvLpuZVPi11jR/A8UnKO9CvsVHIvRPNpa67OKS71NBz33P1y1/mRXU4JeQLQ45K
         36tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ERCa2F3xqM4YYZpkmzJbcUJ2/+E03VdCOWmOVL6AwB0=;
        fh=zmyZiw8D0b8X9heOtPKnfcpgFvPMQdsouHQCC8moi6Y=;
        b=DbgD0QtpKUQ/nrsqzy0LOumVdmqrI9B/WiS6oUs0RZk2SG8CsXp9zHMhSyYcmWCih/
         wakrLIwllyQ7kFgaMpBAO31dJNwY/7OVJ0ae4ao3piM9T2OKfrV8XDxzU/e3nmeVKsoQ
         10c8Xmfypq8NYkxlsqN9Tg7/GG8Dcngh1cZzShuq+OoI9ifxBOGX3PMR9K7rYfeqe7xr
         WtVov81gcspZYLyvAcFO45wtyo9Yh1yH0X7qpObYYPSbQVw8GiTcMI7dQ89lc0JtyUQr
         QOayz5/NGCh665En9UPejC7M8Vj7s2AE6oBx/47pBR9a5lWG7U98nv7WGXAn2I1dSe4v
         iTbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=XkQiBuHP;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747305703; x=1747910503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ERCa2F3xqM4YYZpkmzJbcUJ2/+E03VdCOWmOVL6AwB0=;
        b=PjNPJ8wyk6kaOUJ9b7bV9gONmjTHMx0kmE15L9VecE6XymO1lAbyWFebMGbPH+CyqS
         OdJqGf0GvBDkn+munEuINN+xQ14x7N4uD7+R3Xq4LswZQv1ORCRSqdNOWHipWRcLeFJm
         XmJHJejKpu1WdgePVk+e42H3/RixeUDhbjMZczAlRq/+w96IhKn/gunhSARvk+GItZXS
         LT0SH//u84FACt5VOOoTCvwLdTZr4p9WZ/zrUHWqAEaDhiHq+zXZuFu0To8Qtr4HPRu+
         KX8hZ9EnZpuEmtTnnDytdqrazeB0KZKkIgOAQ8E0rWeJesW/wtcVY5DMwvYjiayH/UOf
         kfpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747305703; x=1747910503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ERCa2F3xqM4YYZpkmzJbcUJ2/+E03VdCOWmOVL6AwB0=;
        b=RcXe8QiFRqa6Li4tQr+S2vMhVu5ZDRZbi0b2TUSXSqAocDPYF/KATg2bNtcR7QFX5H
         Ef+Qy8d3Qk+k4maNQ7LzMlXN9+1cJk8TmJPPrTvxWAxFYmvc10V0T+UUlDj+MhIitC0G
         NIs5dK8oFCol7xPQfaiiVrex+s+ATZAjKPQIydCmZmzohOrqDuSxDNVnuahUfvWKoij0
         brZrDqboErbzMbNVCV6Iz1PMzU2FojG5HMTwCZZ/TIjsewNMAzJOH3v6WnHVyO75vafV
         gXxE1kMkOMWHQa468jOVbhhhRQ4WcZwZGPOFxm6GhNbqHnu99v3K4sP33wt5N2t8v56l
         aM7A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUawaD22aLxVSYJtnEidhS2V9Mwp2TkS85Dmg8K6mvnAs5TscPOwn10VcZkpAf/VDTvSjTGrQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw2NY2G4PFd5fAK8oKBlyiTQEVlUDj4oB9yb4pamn9jY2YUiUfh
	PdE4osKA5b/DKHv0AgedZhEDtn4N9k5UIPZTAbMeqAXOKhVXFnOj
X-Google-Smtp-Source: AGHT+IFL1ZKlDQln3z9ggY+5BDzqhBJuOZXJOV4RAc1zPtwOxNhWnYaJNXrdXq1gZGXCXCAcyaAArA==
X-Received: by 2002:a17:903:1947:b0:21f:7a8b:d675 with SMTP id d9443c01a7336-231b60340d4mr27664695ad.4.1747305702541;
        Thu, 15 May 2025 03:41:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBG5Xnr0xwPjKy288Rq0BE+7klENpXNSN/rZQqkqdc0luQ==
Received: by 2002:a17:902:b782:b0:22e:53f2:59ff with SMTP id
 d9443c01a7336-231b487da3els5515425ad.0.-pod-prod-06-us; Thu, 15 May 2025
 03:41:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUv5Ufo1n6OjirrLizdRrJXBZ1akhKf8vD4l8xgjF0ag30sbbN/qfspBwkM3M6wlap/om8riCT3bhA=@googlegroups.com
X-Received: by 2002:a17:903:f86:b0:22e:5d9b:2ec3 with SMTP id d9443c01a7336-231b60aca37mr24552725ad.30.1747305701339;
        Thu, 15 May 2025 03:41:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747305701; cv=none;
        d=google.com; s=arc-20240605;
        b=kBWZlPWQqF0UN72Z34C4XAtFBl+dOZcc4mBLLiVU0MEgyRJQqJtHayA7BdDPIInLbl
         hIJh9Xw8l2VFXLD5XDbAOU4l6JKOUO3rjmhEVu9qMHsDRyn7ll9IFwxPijfjS9vZr0wy
         TIkxw+6lgqEI5jbxQlrNmEbFp5XlDbXC5e4baE09d/b7lVRrQrnlWHTd6v0EWCmYRsxN
         QDBEtGGMyyVCFRB0KWnxRruiGJAO0idDrugrFcUgA04j0BbNIBu9qu1fgeXLuPoXhX4g
         zKckQLVD+e7u3rbea1l+6s07IkZqianMM98aJbn3JIP33IwPWvZ01zRnejboq9COCQKr
         cilQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/u6sVXUmIl0OU5rt4LugTm5/9stFbB2bUferjR+mw2o=;
        fh=oADELe+MrgDAkvHQCdYMPl5q5dxAEqRxUZV5ZcA11mE=;
        b=ZGHYrkewk9pz0ZEV/kQ0tw0wy6NCPJ0w98DDrUVs879y/YN+rk5pnu3ag/ohUfAwbf
         q+xCoGk1glqKOHuo7mrSvri4J1u9TpO8NjS4psmShUv4IPiI2WrjRP5o7sp8OqzhDpRW
         p+RptGfrXxkYU/nk3fWI1kb2ntAnP2mIPc351QSW9fiPqS1m+TtTSdk72jTRF4WKyvT1
         QDq7ePZQBBlrO9i3QtgDZcHibtzUZCHDoabDcwO8d5GyqDMPrRBf2A886XwqoZln7HF0
         iSOR+bKNJzTlbw79wR+m4mao+Z8SSOVFPZeuNQKl2b2vWzRYtLaboMeeTFedDTgA3J4a
         eRXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=XkQiBuHP;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22fc713d923si6799995ad.2.2025.05.15.03.41.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 May 2025 03:41:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54F9F3gL017659;
	Thu, 15 May 2025 10:41:40 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46ndfjrcg6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 15 May 2025 10:41:39 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54FAfddN013212;
	Thu, 15 May 2025 10:41:39 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46ndfjrcg0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 15 May 2025 10:41:39 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54F7F2G3021396;
	Thu, 15 May 2025 10:41:38 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 46mbfrsp0g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 15 May 2025 10:41:38 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54FAfaHG58786254
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 15 May 2025 10:41:36 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B053820071;
	Thu, 15 May 2025 10:41:36 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9BE092004D;
	Thu, 15 May 2025 10:41:27 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu, 15 May 2025 10:41:27 +0000 (GMT)
Date: Thu, 15 May 2025 12:41:26 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Daniel Axtens <dja@axtens.net>,
        Harry Yoo <harry.yoo@oracle.com>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v8 0/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <aCXE1p4+AiYhGAuV@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1747149155.git.agordeev@linux.ibm.com>
 <53a86990-0aa5-4816-a252-43287f3451b8@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <53a86990-0aa5-4816-a252-43287f3451b8@gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: dzjBTB1YXB_GH0AY4aIS8luY9AuQsR1r
X-Authority-Analysis: v=2.4 cv=ecg9f6EH c=1 sm=1 tr=0 ts=6825c4e3 cx=c_pps a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8 a=c33pmkp9q3dSwcthHBMA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: eLYookaplGgxG-G1m8c7YaaHlMPNOwHB
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTE1MDEwNCBTYWx0ZWRfXxJAAEzW9p62n eD0G3GXOh/v1Rdf6Tztkey5ALI1/qRAnIJOP/FnPMyDC2GVfQ7ZSXzO/adPnbR/GjqzUsyjJL5f bexw/87v0sS0Rjounzdo4P5zO906eIqq4pa46Dgr9RTyDm6iDVljI7a++lEclNZHoLX8HJr6Q41
 fCuHfMftHJPXRszy0B1DuwAPG+8VpkE2zVQQHM0VA0gEqb0sngRK3UjKoz3i7YgM5mr24PYF8aZ JfdbgXx69HalthV3AunVbN74Amv+aXo6ZI/krhACzd2f2YQr2OEIwrW/scs40CABp9Hv1g6CjTC dX/Z0bDYtSSMf/fb3zb2Z/rTtoLZVEhJgXOquXpk0ww7tgTWlCTeLAKd55GKBjlr67n/VcceMMM
 k5HC4K1hpEK2UNQMEiop5JficUKNKypkQSEETGISYmW4Sod/lzXv/XjNoaabrXGBXy0CAIh/
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-15_04,2025-05-14_03,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=376
 impostorscore=0 spamscore=0 clxscore=1015 malwarescore=0 mlxscore=0
 lowpriorityscore=0 priorityscore=1501 adultscore=0 bulkscore=0
 suspectscore=0 phishscore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2505070000
 definitions=main-2505150104
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=XkQiBuHP;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
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

On Tue, May 13, 2025 at 06:43:56PM +0200, Andrey Ryabinin wrote:
> Have you looked at boot failure report from kernel test robot ?
> https://lkml.kernel.org/r/202505121313.806a632c-lkp@intel.com
> 
> I think the report is for v6 version, but I don't see evidence that it was
> addressed, so the v8 is probably affected as well?

Yes. The problem is page_owner=on prevents bulk allcations.
I will send an updated version.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aCXE1p4%2BAiYhGAuV%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
