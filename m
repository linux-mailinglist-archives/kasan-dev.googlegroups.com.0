Return-Path: <kasan-dev+bncBCYL7PHBVABBB67XZLEQMGQER6BRC2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EB65CA74B1
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 12:03:25 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-88236279bd9sf42833906d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 03:03:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764932603; cv=pass;
        d=google.com; s=arc-20240605;
        b=XD16ojaCrtxy4cfYIkbDRLWfJny4jND3EJjLBn5zOA650LvMFbcFbNfX9a9urZhK+U
         jRJIsVDEFU7PM/xNQcKRwmwx6ryMAkpW+y7/S+liL9uC+Z+gVhVlEk/0jYp68QRAivjy
         QcWDlPLvnjRn3K+1HAqomjvkvR/b4e4AoLsF6ZX/+10alZZmO8q7vBxytwJfDKN1nZ/e
         9f6QE5O4U1/G2pgPoJiyqrBRT2SmlukUIflsc/jmAtJyBijPqVp2YXCaLRTzUTlFEG4G
         RF6SFbJHFtu5aMnUZS8rT54zAktl1DanZxfRTUHI59kkBl8IsNg9pJnzkkPJ3dG0tr2C
         t0Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=VCqJcnUjLtbnxM9dBLIZJOsyD1fibily4JU943VdkTc=;
        fh=BLx905pqub1gNL+RQLeqGRjv06Fu4AhYMyg5IOr5Nxo=;
        b=khW9IrgAkjlU/9cJZq423ke5nbsyUf/4DHg/EYk+xym2NKsp6MBNPFtdCcW39WCo3d
         neJEFD5icoXhII8nLqPsLX5hu22MpCufoo66tZaSsXNZ+d0RvcO98lmlBscfuc0U/clB
         /TJsyBfVsGci5LYwHBOnKsjHQ84XvR0GWlZ+a+xxLAiyXGMkO0LLgk50bx5TYCtwPAjX
         fo8AbuAUyPEaEoS3Xi4WV1oo4mYse1p4ltyor7jzVpeavH0GCZwktAMXbxbM0RKjPYsa
         bWcwgZ/He1h11OyB7TqwA16D8zONlo5EbtBY71LihYZNzV0mpiSoL0nziwTf+jGaKZw/
         bsWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Jlk/tWqS";
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764932603; x=1765537403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VCqJcnUjLtbnxM9dBLIZJOsyD1fibily4JU943VdkTc=;
        b=c4nmwQcSwUIAs6IOkoBY9SldswwPJo9+SNuBVcx83lY93IvFJBaaJ07+Xygsjw1Izt
         TE5OPp3T8pff/+R3GP+QczRoR6x5p5h/v6awWtB/vjrifVYuXTvNSm9p7/B+95xMGDuT
         q9UynDJzCXzrQGTZA91mNJHVvdx30rxVKAUucngvc5jJD4lg/brFF13mDElKsDJzOh1E
         YuzjRGImwJ907RpmBOiyCf2lOQM9ftDDfFZYqtk78AKvkUOvkKhoaWw1AsoZc2vEX2GG
         ryQyba16pfpQMZXDKAM7mpLnKqja3tyXP+0H6FUretme1C8GZpTXEJhkBJSE6WrnVosw
         6R4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764932603; x=1765537403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VCqJcnUjLtbnxM9dBLIZJOsyD1fibily4JU943VdkTc=;
        b=HPekZqEmm5QUBBNpAVA8mWCyF7iRItJjtzScIiECRCvB/VocIOPJAKs9wchyT0Dc8Y
         y19LiE4rKocEljLXPO67u34KbhKbqA0RK7vYeBDL5XMBmoI0YE73gllFKixSmjR7WOWa
         VyVC7XeDmlo1ird8GY8zhlEUsl6s4zo5L2A2j5FWZpVwdL4hPUgVaiAG91fHbuYEGBMw
         emIn6a7/WXQqqBIbiZEiJgtFP4mU/U/FcBPmZvWBpORTzKQiwDkS6gwCWyXG5cqnsOhd
         UN4DYCGIn5Fol40zCjGiz5TJV8ak2fB5mfI8JBebU3kUYJHqcSWWvg8W4RcEin2DKckV
         vXpQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLp/lC/i9FxhsxCnRM22M5+bjsEFEdXZJgR89b5+Uf8w+aVC5rOd+liw4RfbDCJ+m/nMjseA==@lfdr.de
X-Gm-Message-State: AOJu0YyUYLuBCRy/XVlXnZrHuITMqrj47JrUJ0PAyzmxQyIZB0Wu/VhX
	UCiNG3ITp1ohqhr37hYTjvIjZobPQ+h0G8zKRL5Si4RkfYSfV0ZKfjj6
X-Google-Smtp-Source: AGHT+IG0bMdImIUugotlhB3LsvsTtI/yLPQSMkdGVThenv7axnWDbVKVZmHOcw9quUbU/MPht9ge3Q==
X-Received: by 2002:a05:622a:4c9:b0:4ee:24b8:2275 with SMTP id d75a77b69052e-4f017544b24mr117766071cf.1.1764932603556;
        Fri, 05 Dec 2025 03:03:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aPocNYR0h6SuflgpaeFUokTcikKGLUoJtVE0H/Eb0nHQ=="
Received: by 2002:ac8:7d8d:0:b0:4ed:9424:fa31 with SMTP id d75a77b69052e-4f024c53e91ls38054041cf.2.-pod-prod-01-us;
 Fri, 05 Dec 2025 03:03:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVgNLxZ8xjohJwjzfj7oVn7cR0kVOzJVHluhYR8WdBigrG/Vm9gwIblYoKclZkuTIjCX5t2Emkt9aE=@googlegroups.com
X-Received: by 2002:a05:620a:4142:b0:8b2:f2c5:e7fc with SMTP id af79cd13be357-8b5e47d00f9mr1171072785a.7.1764932602453;
        Fri, 05 Dec 2025 03:03:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764932602; cv=none;
        d=google.com; s=arc-20240605;
        b=NpTucYdUvYZz+tC6mRNUA5XsTNXJfDn6GOehZiJ4VrbPw/8GZkfZXIFk6SlWCtmKk/
         Z22Ocujr3KES51CYaIxvTPYWuM0zAx+s7/tvM1/b4SpGVvZ+E1ZxzL9rorIJqDxCPE1A
         ohNZfNsc/o28Qd8DID5c0YSWzFSgXkKj2BMK8nYwFc+VsuwScTimIlcU8DN0xBpfuVJ/
         IBbO/3WyHcVoo4tWqv90exyUCImpdV3iybAxxPSn7E96YkBaes9ZM4ynozNfMAQ92HG2
         zEuR9aRKVfVP9I55EiR2gY71+mMY0HyQtSmrjFW2ctnk+6ecS1RKngwVYCeTLOGA5DQE
         g5hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=FJmrnVAWmxW9nZlblGKQ8BQKPdrOnw9FZ2cIhgKrb+M=;
        fh=AfRUPD2rILy7CI5bn1QhUMrB/N7K+bER8eCSGHvx5uk=;
        b=b9mqIMkiyZI3EVZUQU/b3RyJ00aybYEPqQbErL9Yg7y5c/nL1ufkKv7YM/FNnehRrA
         YYJt/kOH4+ZPehY2U+rEDWEGaU7m8MJzc6zQIXFzH0KNT5gOsj4uSpQ1EJBiybqndPjF
         F4hFZM4GJ2aiby4L7Ns0cC9sbPdQBZIqLNDGE18TFa17pbGSR87b/xbhymadhiu93K5E
         FMjWUNDG9IFmXRfSm/E7dj2YD++W97MXuOCmfaxii3IjMwRuPnjv2MVQ7mI0DLLNuOw0
         nQh8Kg7XZ9z5yiFNtJqWPb0TWVxBtmpYnHDg4n3QefDI/XRd7h3oyFCYMf3yykqAT6Cv
         dbiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Jlk/tWqS";
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8b627acd454si20628985a.5.2025.12.05.03.03.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Dec 2025 03:03:22 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5B50btS0008539;
	Fri, 5 Dec 2025 11:03:18 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4aqq8v4kq3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 05 Dec 2025 11:03:17 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 5B5B3Gk8027460;
	Fri, 5 Dec 2025 11:03:17 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4aqq8v4kpy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 05 Dec 2025 11:03:16 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 5B5A8Tdb024045;
	Fri, 5 Dec 2025 11:03:15 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 4arb5sw0m3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 05 Dec 2025 11:03:15 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 5B5B3EQ738666604
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 5 Dec 2025 11:03:14 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 10EF320049;
	Fri,  5 Dec 2025 11:03:14 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2CED22004B;
	Fri,  5 Dec 2025 11:03:13 +0000 (GMT)
Received: from osiris (unknown [9.87.131.209])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Fri,  5 Dec 2025 11:03:13 +0000 (GMT)
Date: Fri, 5 Dec 2025 12:03:11 +0100
From: Heiko Carstens <hca@linux.ibm.com>
To: Baoquan He <bhe@redhat.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, linux-mm@kvack.org,
        ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
        vincenzo.frascino@arm.com, akpm@linux-foundation.org,
        kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
        kexec@lists.infradead.org, elver@google.com, sj@kernel.org,
        lorenzo.stoakes@oracle.com, snovitoll@gmail.com,
        christophe.leroy@csgroup.eu, Mikhail Zaslonko <zaslonko@linux.ibm.com>
Subject: Re: [PATCH v4 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <20251205110311.11813A10-hca@linux.ibm.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
 <CA+fCnZcVV5=AJUNfy6G2T-UZCbAL=7NivmWkBr6LMSnzzTZ8Kg@mail.gmail.com>
 <aTKGYzREbj/6Hwz6@fedora>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aTKGYzREbj/6Hwz6@fedora>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: Eym7r3xetcUFAk65KHhR67Lgmhyr4aUZ
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTI5MDAwOCBTYWx0ZWRfX7B7O4z0hwN0F
 PgOIq4ByAtB986RdaLRKvfuMymJWSwBG8yT17AQ+IHImaU5V4iKH22yS3C5KzddRnwhm3s5zhty
 J8dz5GSoaKbQ+QWsxQ/IMQIucT0AWhv6MkKp+FXlGEa9GYbg7YSn+ENTKp/TTwFRLBsoSbxTllb
 qvSSpl3oy3rGiW3WU8mRJyX4vV194CHOR93yKCJvGX2OKBr1BLyZUfduF/1ZL7Jy0g0ahlzhDGL
 q9S00qZyEdjOetvG31YFmuuXki4r0/7SHZr/UJeTmmxjCri8M+QGhX4rmnWXPlxoZICqVXOmPH9
 J1Sd2B/Ip0yIec6pnApVTgi8T9oMnMA+jxyng5MunAgiMX4gDXab2LXyFkn+hoMmV1m+DlossCy
 o4l0uJ04VKST6L6MWkGhMoRvN53nfQ==
X-Authority-Analysis: v=2.4 cv=Scz6t/Ru c=1 sm=1 tr=0 ts=6932bbf5 cx=c_pps
 a=bLidbwmWQ0KltjZqbj+ezA==:117 a=bLidbwmWQ0KltjZqbj+ezA==:17
 a=IkcTkHD0fZMA:10 a=wP3pNCr1ah4A:10 a=VkNPw1HP01LnGYTKEx00:22
 a=20KFwNOVAAAA:8 a=40HSkAYmfyoHoQYM2uIA:9 a=3ZKOabzyN94A:10 a=QEXdDO2ut3YA:10
X-Proofpoint-GUID: oD0qT5z5etYDFvofq45rGIQq18lrpDXv
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-12-05_04,2025-12-04_04,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 suspectscore=0 phishscore=0 bulkscore=0 lowpriorityscore=0 adultscore=0
 clxscore=1011 spamscore=0 impostorscore=0 priorityscore=1501 malwarescore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2510240000 definitions=main-2511290008
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="Jlk/tWqS";       spf=pass
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

On Fri, Dec 05, 2025 at 03:14:43PM +0800, Baoquan He wrote:
> On 12/04/25 at 05:38pm, Andrey Konovalov wrote:
> > On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wro=
te:
> > I also wonder if we should keep this kasan=3Doff functionality
> > conservative and limit it to x86 and arm64 (since these are the only
> > two tested architectures).
>=20
> We may not need to do that. I tested on arm64 because it has sw_tags and
> hw_tags. And if x86_64 and arm64 works well with kasan=3Doff in generic
> mode, it should be fine on other architectures. I am a little more
> familiar with operations on x86/arm64 than others.  I can manage to get
> power system to test kasan=3Doff in generic mode, if that is required.
> From my side, I would like to see x86_64/arm64/s390/power to have
> kasan=3Doff because RHEL support these architectures. I need consult peop=
le
> to make clear how to change in s390. Will post patch later or ask other
> people to help do that.

We are aware that s390 support is missing / does not work, and will
provide something. I guess something based on this series would be
good, or are you planning to send a new version anytime soon?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251205110311.11813A10-hca%40linux.ibm.com.
