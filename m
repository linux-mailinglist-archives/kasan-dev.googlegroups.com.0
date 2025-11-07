Return-Path: <kasan-dev+bncBCYL7PHBVABBBQE5W7EAMGQENO4K7YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CFF8C3F91A
	for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 11:49:38 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4e88947a773sf24368701cf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 02:49:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762512577; cv=pass;
        d=google.com; s=arc-20240605;
        b=U0iEQDCvZk0v96JwDTxQ9cLZx3sBiq2xEaCG0nzR5o2JiSg1w2ZFTA0sGM/Q/3fy/J
         zvE4YoD80AZwF1nIxzVQ1Eyl+fk6Ozr4cLbVnpyFPkGVycjHHlY5/KPrbOjL/Qig+foi
         aCip2foGmxy6CzvloYaZ/O78uskFvalrMjzmYQgfJ8lT/r8s+Xp7zBMV2cnnoRgDQcD7
         8S8mDZXiD6b/0fxeu6H4aUdhmPrmeamUZwmTyD5pEaY4HJrjMWhoHRxHgy54tAHPV2ZC
         Grc6eLJcfu57meY89KV5nR1hrdYBNIOmfZmER6MszOBAZxsd7DibGDjCS4Ck5+UpnCde
         pfHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=A4fK4cbfMXOxW2ltSUPs05gNLYZx2ATxcoqBZ1Cmy/o=;
        fh=jmz6u3TUoX6jb/z2L6jvNmcqp7yYnSKomr/XfBvI4qo=;
        b=YH90Z1s8mWMIh6CiOJF4kBnE9Sbmwp36TmuKRtOfFLJ07dxvKYdNh564Yq3WnF2vo4
         tExlp8WEenl6rWznKZ2VKcOzOj24EvymBGIg+t/NKzEbtzwIB47PRw0zkFqq0I1YCUgA
         9txUfyJaTLcftXinb8W5gynZTLD++IIyDvb3jTsioQPHrmsqAJI12R6eMx7IMIxaPbXL
         a/6Jdc80Pqj+28XjJ/d+XYO/WLTjJA8GXkQTeDdxkqxdzUOo5koagvcwIkDC2anHURYs
         ChErHE6dj8F3BBFD8L4b1rIffeCPo/pM/pvOAsoVa4aHiG3tnRUyCmsqKJL3xIMHOkQh
         Ia0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="eUoI/gb2";
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762512577; x=1763117377; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=A4fK4cbfMXOxW2ltSUPs05gNLYZx2ATxcoqBZ1Cmy/o=;
        b=TzPo+Qiy2tqzz60/CSmUB1RNri+skqOMl/gsJjERThDN6DV/+a5PTgb/ePrsC100iO
         usYkwa6EmXJkY1l3Bd3k6jlsxXbio2OcWDPEi7UchOmnl7yU3FASt0HbzmceQfxN1jyA
         f67sfjrXNP7mSBjdnIOmcnQbjfUYSIT+KERHIjVy5gcUf+qY5ynXjtw3yfkxRau0f5pr
         lFhHBVqIeGfqJxoJ36+xPjtL6RLWjx4IWz4x8Y0zaU+4VOWe2YednGVUAOVtFSRCxHCW
         v7BRs8cRPl0vR3tWPoP4CFAs6Qh+hKxhDogA9/FG2WRW7ASTkxJroNnSoC4AqNmKO7GX
         vqTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762512577; x=1763117377;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A4fK4cbfMXOxW2ltSUPs05gNLYZx2ATxcoqBZ1Cmy/o=;
        b=iYqeQqzomxoVcHUJ5p+k1trjxV/5A3feTU8lmPA75fZJqeqJDsAXNIo8f1saIqfrdB
         dyPbLVwfh/+by6KO/GYffZFtgK5K7PHCwL8amv6bDzbVZPMncy4REBP1iqh3mIzDJJ4L
         HhepryCHjunlYkIacbPqWLJdW8O62M586lqTwEw7JIdods8dyXBvXL8sGEi7yGh/VCzg
         JcOKlLVr9omrvefwePr+auSoQFTCgklWi6zompMqpCEa5zi5QvpyWT+96Cwr4wy+u/+w
         iWk4Hw95jy0ee9YIv6M2sH4QRwR+5v0vHQ9M6HEFSWzfdwmjAahe1GruRfIdxXOsNpGW
         CHoQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8/wb2ydpo5X81U032IkSQa73qJks1cXQzwOSniVZnXjWgI6eaB3utjYDAUHiYxrNVANtMHQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzi6Fu8zJWdQTRf7Lt2NB+3p2vkxIBpwkf5cgol80zeWmlamE/w
	AMbYCcckNQzTaeSrY5whkTEUh5Tw7AXHpweT7urzpnw2q7gwgWqNzPTJ
X-Google-Smtp-Source: AGHT+IG/gvnXlW8JOz0BlvD9WCbMOKFa5lVmC0g2lWnXphmW/u/HIKQpza15JLgVRcwRxduZU2Rjlg==
X-Received: by 2002:ac8:7f06:0:b0:4e8:a115:14e0 with SMTP id d75a77b69052e-4ed94a6d59fmr29895291cf.62.1762512576767;
        Fri, 07 Nov 2025 02:49:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aMUDx4tnobhfwNRgTqGy3beiEUrdNy4wHBlTsxn9trJA=="
Received: by 2002:ac8:5a88:0:b0:4ed:7903:e889 with SMTP id d75a77b69052e-4ed80f6d1f2ls32860171cf.1.-pod-prod-06-us;
 Fri, 07 Nov 2025 02:49:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXTLTk9EA2gT3lX8kwx9LQYsgj+qCLhVMLaLpeUbs2ns9jmmSqrm2durzbAxhUpSCa1s3g6VUnnEkw=@googlegroups.com
X-Received: by 2002:a05:622a:181f:b0:4eb:9e22:794f with SMTP id d75a77b69052e-4ed94aa20afmr27865271cf.82.1762512575870;
        Fri, 07 Nov 2025 02:49:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762512575; cv=none;
        d=google.com; s=arc-20240605;
        b=IP5XERTmT8RHTqzSdN8MjKDnLTkPZEpS4Pouem8JtQgZMLbLQzX+616M2uNUMzk/tv
         f+UvlrVCneONloTYFC2NlrbH+xElElnW7Nx4UVdCtHag/xD2uFJEQCWxBhtsqjhbTueb
         LZvnQN9PsjLwimng6rPxPIyojZG62ylmdKxyj8vKXtNmY7mTe7gI+iG6I9gP06CID24u
         eue1tZdvFJ8x7hFz/RvTVo7418eUpgXhsXk8o8rfpWrY6xT8kXHtg5tFqFvK+rH3bEMO
         hjnCW5nxtYrOzm3iQdpkHVCDvWtTJX7soUZh4YWeIgGFJVwXK0R+K5VLBs1wfwaTslFn
         olkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=dQNXGowmegNUGhw1zwL0CSsOd5LGDJmvsS5xKvlrqhY=;
        fh=ONbAHmzcMDoMrZVeZZ6oo9UICRWSG0cs3k0hUgW3qko=;
        b=NoEUQlukhvJpNBn5fudL7j+m9VvKjk+PZ8WdCAtobgJ5YnE6ByvlltDj34B7CX6Z6I
         88OBnAyRPrWXhoDNFcw9UJXro6wFwDvkVCxEBje/8zTCdARzW0TE26xT0j/Tbd6tigCP
         mQB5tEBB9qxOvAfrwQnqxqkDBwU4SpUFXZFN1V6sO06ggnGnMfIRtw7RNW6YasyL9JqP
         gkpBf54gt6NFfwjL8cm7FM/E0OZvly1OPhKd+MoGL2i9+rKlS6kHVPRUBUCW24ad1x8V
         dqL5/kjTGlSkE26y/MWhkgx7Q2x1VxYgZmI+j/zAb/KU6QuQF47xTxfQlRyGJUb9TV/Q
         t7gg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="eUoI/gb2";
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88082a521f6si2913176d6.6.2025.11.07.02.49.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Nov 2025 02:49:35 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5A78Rkns010216;
	Fri, 7 Nov 2025 10:49:35 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4a59vuv80v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 07 Nov 2025 10:49:34 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 5A7AlRSb011750;
	Fri, 7 Nov 2025 10:49:34 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4a59vuv80s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 07 Nov 2025 10:49:34 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 5A77889A018667;
	Fri, 7 Nov 2025 10:49:33 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 4a5whnt6tc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 07 Nov 2025 10:49:33 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 5A7AnScR9961806
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 7 Nov 2025 10:49:28 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8D5BA2004B;
	Fri,  7 Nov 2025 10:49:28 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A35AD20040;
	Fri,  7 Nov 2025 10:49:27 +0000 (GMT)
Received: from osiris (unknown [9.111.32.237])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Fri,  7 Nov 2025 10:49:27 +0000 (GMT)
Date: Fri, 7 Nov 2025 11:49:26 +0100
From: Heiko Carstens <hca@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org,
        linux-s390@vger.kernel.org, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>, Thomas Huth <thuth@redhat.com>,
        Juergen Christ <jchrist@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: Re: [PATCH 2/2] s390/fpu: Fix kmsan in fpu_vstl function
Message-ID: <20251107104926.17578C07-hca@linux.ibm.com>
References: <20251106160845.1334274-2-aleksei.nikiforov@linux.ibm.com>
 <20251106160845.1334274-6-aleksei.nikiforov@linux.ibm.com>
 <CAG_fn=WufanV2DAVusDvGviWqc6woNja-H6WAL5LNgAzeo_uKg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=WufanV2DAVusDvGviWqc6woNja-H6WAL5LNgAzeo_uKg@mail.gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: xHt6csdp5zIfKXLlO9Ptb7N1pvutAy5R
X-Proofpoint-GUID: N2mW_1T8BvlehvL96DCCIfaE4a4UDLER
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTAxMDAyMSBTYWx0ZWRfX2h2be+m4QKUF
 TMK0Rma4nsce0Rxtn3dZvd5VoQb1zdv5Ed2lwon8EFuSo6iCgmxqT9V0zVDfs9Ib/AROjhjNIEC
 7jJhaKBUToU8DAXSIJ0eb/VILLPl5GWE6jhg/2AWY43qAk2XGIbQzhYcxtrc3kDhcu6lWwx4rkI
 KN5PnPZT3lHKBhMCapRRHoKFX6NryZhWdFgLcJ0ot0eM4JGBvkBpx3pqhuc3317jTIUGunpSXm1
 VQ1XkTqk3Nc6yInG/WfNEkP4CgmU2tbpTSaoUc0m/1YdeDvm29gKi49Zz9TlJfewCb2MEs/ZXQy
 jIZYbgTCtnS2ZtlxlrpKcDqmE6mslnv20EjnFyGbNlo9COA1beVHSzpYA+Df4qKw0wVt8TNs0ig
 +QgcoX50Idh1L15KjpnY7Ws/7aATGQ==
X-Authority-Analysis: v=2.4 cv=U6qfzOru c=1 sm=1 tr=0 ts=690dcebe cx=c_pps
 a=GFwsV6G8L6GxiO2Y/PsHdQ==:117 a=GFwsV6G8L6GxiO2Y/PsHdQ==:17
 a=IkcTkHD0fZMA:10 a=6UeiqGixMTsA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VnNF1IyMAAAA:8 a=pNHI5jXrFARJaYZssDMA:9 a=3ZKOabzyN94A:10 a=QEXdDO2ut3YA:10
 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-07_02,2025-11-06_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 bulkscore=0 adultscore=0 impostorscore=0 spamscore=0 phishscore=0
 clxscore=1011 malwarescore=0 lowpriorityscore=0 suspectscore=0
 priorityscore=1501 classifier=typeunknown authscore=0 authtc= authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2510240000
 definitions=main-2511010021
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="eUoI/gb2";       spf=pass
 (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as
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

On Fri, Nov 07, 2025 at 11:26:50AM +0100, Alexander Potapenko wrote:
> On Thu, Nov 6, 2025 at 5:09=E2=80=AFPM Aleksei Nikiforov
> <aleksei.nikiforov@linux.ibm.com> wrote:
> > @@ -409,6 +410,7 @@ static __always_inline void fpu_vstl(u8 v1, u32 ind=
ex, const void *vxr)
> >                 : [vxr] "=3DR" (*(u8 *)vxr)
> >                 : [index] "d" (index), [v1] "I" (v1)
> >                 : "memory", "1");
> > +       instrument_write_after(vxr, size);
> >  }
>=20
> Wouldn't it be easier to just call kmsan_unpoison_memory() here directly?

I guess that's your call. Looks like we have already a couple of
kmsan_unpoison_memory() behind inline assemblies.

So I guess we should either continue using kmsan_unpoison_memory()
directly, or convert all of them to such a new helper. Both works of
course. What do you prefer?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251107104926.17578C07-hca%40linux.ibm.com.
