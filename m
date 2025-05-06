Return-Path: <kasan-dev+bncBCVZXJXP4MDBBT6N5DAAMGQE6APQU7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 81A93AAC927
	for <lists+kasan-dev@lfdr.de>; Tue,  6 May 2025 17:12:17 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-708b88ee61dsf80236987b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 06 May 2025 08:12:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746544336; cv=pass;
        d=google.com; s=arc-20240605;
        b=JNj3QQ8swKhrhXIn38tm+e22EY6FOHZO59VDlW8AIEXbnuTwgZbTtdbZZF2sD3bnxA
         3zI/SVFbzaxMzGHQgGkaxJ+qg+nOLIqz6iP8PjSkyJKfTHgvxsaqEtiG0JoE+slyXGoe
         qf2wcHI9noyC1eLhBxIVFD3g3VqFifYZANOfbgAmiXTBiI4l5Pdk477XHl79u/MAapDs
         mO112CIVkqML1OsQwI9S8wuQVrvRNzHbdxP0wp+ik1Rqkk1Jq3MElpbl5QV3XoG1N3ZK
         FgMmYQS43ogb1msCHgbDbrA4zd1RT3HvDnCyYUkOrbM207a/VBlMsab5TgUodxyhjNd0
         iLNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=O+88RsvRuHWr1VmkracYCIJVHPEQk24/Z6jv/x92FDs=;
        fh=UOCOwk/Vad+d3inAlfEZPh/m+lAuJlT/s+reQvZM67M=;
        b=X/TViSVkcmHDnbrX45YGRfHWlI4rH0uLeDnykvPFSMQJX89jStg5v5RScnQIjmGloN
         5dzSxp+ALIINDw4U6JQTSzQGqu/duvQUdKUxYFUwnKateJjWXwvslciuYrxIUvURBkz3
         YF7JiGGj1B1ORXqczpwfw1Sc8i/q3CSwjSSdjMzKaCu7p7rZvOm5ePUa1smAykku7oC3
         HD69sSLqhuLLQ4HHQEC+Ek0kslhCBl/dkv4F50NuGa/6cIDh2HzI/hKTyaN+XBReT5br
         Sd6yzbIJviUCublhFXOwwwN1mQYa6sMhe1whQb6Nc3rx7qIH63vWgurJafIIKgNc31Dl
         OTrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IBGWaweE;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746544336; x=1747149136; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=O+88RsvRuHWr1VmkracYCIJVHPEQk24/Z6jv/x92FDs=;
        b=SQ7cu9HOb70wh49ckkTJUwgMFp1WCjsRdjVEFSyetVfHw2RQ3aWnuunxcl7VuNOZFz
         7j7aoykX7Vo5q6l8LJ8yQYtykiH4yF00Fh3fS7nKc7sQz/ysSqhPTvBY72Mw+uA6/jF1
         g/vUrWltCAPwyJfd3IgZKSEt6ZC7c2+rumYRNcK5lZcYtUowp/txh06gYSo53pCKRA6Q
         gUSrH0SN43Oi5vEjkuZW3hwnnGk64MURveU4ovG2kergO/qUSReBmoB/8nJ/G6m16091
         zrTIeDVMexqqGKWiPNxqF7nxLp6PVuD5eSaYn5U01jFTXunzDABipnBYQ/iSFZeegPLM
         g3+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746544336; x=1747149136;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=O+88RsvRuHWr1VmkracYCIJVHPEQk24/Z6jv/x92FDs=;
        b=VrMbJZZrH2p4rENnNDvZz2C7RrxR6NuYAjA2cQ786scQEG/oiSE0eLVBqEeCN8K8+m
         CDHAbW+5Le0ryfWlUw4ENsRxfK2CJk0nA3+tMVNfVRrXKYqE6ucg/eENgLHxiJf8tJAn
         UfR9+qhsezT9ApuS5Vz6KiDWDMLP6cfJEkzGJ/D/zeTeJKNdgLV9b1yYdfmSahAwmnBY
         rFaj9vDmQjhw3xuomvoHYnIa3NDZjwXLeGjTgHJ4Hp5kto2RGbIobMaM4KwjYsgXKc+9
         nnkbVDLr0QaYOjr3RVCbUlUh4QOTXNrAzPck2SSmNgRQoKT2EVEX0LnZGhb8ZJJorI9n
         +i+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVqbZ4xEg2+FbgSrumQLHpGr0A9bB5/MDmms6bJIUeR+sD/X+/G/jQ2W/hAwPu6Si8qnZkSig==@lfdr.de
X-Gm-Message-State: AOJu0YxTVCZWQ6nDP9WLykSBNjkjEuX3iCLm6STyE1CqWaZ44SI8qEyu
	B5LYTQsEIV3POED/sjmmLwauHlRsR3fUuQbFGu3FoydkZRxOfft9
X-Google-Smtp-Source: AGHT+IG97oX9iQFk9poaTHHKQEay6CZqRgvqgOK5NkanCRBrmV2Db4A2KapUybDMgdkRtkUtDeEuYw==
X-Received: by 2002:a05:6902:1b8d:b0:e73:1ff1:ca28 with SMTP id 3f1490d57ef6-e78694dced2mr18016276.19.1746544335847;
        Tue, 06 May 2025 08:12:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBE8SPeqT8TJ+3cxR0faKWhe3fKIdJ9znkhL14XkmnGMvQ==
Received: by 2002:a25:264a:0:b0:e73:f467:2ac4 with SMTP id 3f1490d57ef6-e74dcd98df7ls1951806276.2.-pod-prod-06-us;
 Tue, 06 May 2025 08:12:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDZ2QyjHWFZQUHSdNsB9mGJPMFv4ONcjgqabxvyz1Ryc6yvWtPE8jREc0jXkQfNmP4B/OJd87KvNk=@googlegroups.com
X-Received: by 2002:a05:690c:d18:b0:6f9:7fe6:9d48 with SMTP id 00721157ae682-709197aa38amr45651647b3.7.1746544334780;
        Tue, 06 May 2025 08:12:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746544334; cv=none;
        d=google.com; s=arc-20240605;
        b=IDl/CPmGIg4CZUGVDk0r2x9NcLV/gAdSTjMMbBR7VPZlBNi4SM7ObRXsuHVQJmgF6a
         cUPj0F1jgtOv2WdwHDtN+o4jZzvid0zBlMhPiUZURf7wuMeMBSJ/R3N6BAxhmclW9MXw
         FLgu91ReSduKVeb2FFmopD7yEY4IpnsA3GRtc+SpmjY+B/+8zqLGvQiEhQOLI5j4N9wv
         Sq0OO5WlCc7PCYt9oyEqatZP2mgdKXYhIUrhrEy0fsn5BqsvITDlBb4ESX/kDhfHQILX
         xtX+o3SQ4n4I+xzDfX1dVY4nCMk93HBHQC7H726DCD1up352sr9dd6Th/g10R8q0loNj
         NNTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DptX2UeZwcMMuIu3rqeAdS+aATNzHGt6NJTQ/66uAY0=;
        fh=3BQj781ir8/xyQ1Jhse2VYDUohdUchx0ROMGQ7qRODw=;
        b=c3yZe+563xNo+pTua8T4kZEecY19T0blPhnMe/XFq0jZMijOGKVAzmE021hZXKkVNS
         HOTvVtQXcQZcaKCUlMaRsRi1D3LFuOLLh/eurxINGT+MsjvOj9+TBP7vretqp2BzyfPl
         E+Phxj09mjbejay/oT42363aRVO39z0LKwVfRdQEvlog49/yfwuAvvUipqslQhMbMFRV
         g1wBcrxaCBOeboacX2pSw6VcATX5tS+oydTgUEgyUKQZCiquw38pUJUN1jg37RFm1Q4p
         woS/0Wqen3sGC7Ofb/yUzmlA4LZkdNJ+f4jBwp5XaMGhUjVatpP6m/1ZB25niSAO06ue
         ajKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IBGWaweE;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-708c3f0cfe9si4708867b3.1.2025.05.06.08.12.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 May 2025 08:12:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5465gaaF006476;
	Tue, 6 May 2025 15:12:14 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46fcgy2kc5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 15:12:13 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 546F7FdA009118;
	Tue, 6 May 2025 15:12:13 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46fcgy2ka0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 15:12:13 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 546EK3eN013770;
	Tue, 6 May 2025 15:11:31 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 46e062bqn0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 06 May 2025 15:11:31 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 546FBUK835717386
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 6 May 2025 15:11:30 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2A02820043;
	Tue,  6 May 2025 15:11:30 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DD0BB20040;
	Tue,  6 May 2025 15:11:29 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.155.204.135])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  6 May 2025 15:11:29 +0000 (GMT)
Date: Tue, 6 May 2025 17:11:28 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Harry Yoo <harry.yoo@oracle.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH v3 1/1] kasan: Avoid sleepable page allocation from
 atomic context
Message-ID: <aBomoDkNgiEAJjgX@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <cover.1745940843.git.agordeev@linux.ibm.com>
 <573a823565734e1eac3aa128fb9d3506ec918a72.1745940843.git.agordeev@linux.ibm.com>
 <aBFbCP9TqNN0bGpB@harry>
 <aBoGFr5EaHFfxuON@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
 <d77f4afd-5d4e-4bd0-9c83-126e8ef5c4ed@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d77f4afd-5d4e-4bd0-9c83-126e8ef5c4ed@gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: gCu2k3kzWhwCVIxf2DSXQrISTGR2DThe
X-Authority-Analysis: v=2.4 cv=Pa7/hjhd c=1 sm=1 tr=0 ts=681a26ce cx=c_pps a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17 a=kj9zAlcOel0A:10 a=dt9VzEwgFbYA:10 a=7FHASCDaF61PvbNbS9YA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: Gu4J50MXSzFrSjYitZme6bowNsEc1S8i
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTA2MDE0NiBTYWx0ZWRfX63DfIGolAsmI wti07+s8BO9WtAzNDxvGO/1dKf56kvZ6IKPlQVij7HSGJUZxblTqIpVA1OcoyMOxWDrrJwEwvJs RcdN5hLk36bh1CGsIDPnMpf3bDmhJtWMt5hcvZ4F3BlD7gorA/t0S7yjvwFeHfYPr6SYppkvqWn
 3OEf4hDBbauqcJC5kjVGAdx7E2bDtvz6V/onIhQaU0TJmlcRkjUvVGAhMmW0MNYTYu3Xga1jcv2 zTG2PvOWegkCwo7Fmtr2u3E1LHxcSSd8mPJ0FVCdp+04X6/8yEAN165+5mHdqH8gBMy29N4mV8e Ya8VxBIuqa5kan5L91dB46ryq0d+SKGfEk03sPs6p0IDka6wSBQiq/9Z5qPx4gWLM3I1/+jBI94
 YF41ALJMF9Vtf4hZDH5yGEqzQhNpCtQQ/5hqk15VGTb2jnQcNvQIEdtlPxevPQLukJ7tbKJX
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-06_07,2025-05-05_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 priorityscore=1501 suspectscore=0 spamscore=0 bulkscore=0 mlxlogscore=852
 adultscore=0 impostorscore=0 lowpriorityscore=0 malwarescore=0 mlxscore=0
 phishscore=0 classifier=spam authscore=0 authtc=n/a authcc= route=outbound
 adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505060146
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=IBGWaweE;       spf=pass (google.com:
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

On Tue, May 06, 2025 at 04:55:20PM +0200, Andrey Ryabinin wrote:
> >>> -	if (likely(pte_none(ptep_get(ptep)))) {
> >>> +	if (likely(pte_none(ptep_get(ptep))))
> >>>  		set_pte_at(&init_mm, addr, ptep, pte);
> >>> -		page = 0;
> >>
> >> With this patch, now if the pte is already set, the page is leaked?
> > 
> > Yes. But currently it is leaked for previously allocated pages anyway,
> > so no change in behaviour (unless I misread the code).
> 
> Current code doesn't even allocate page if pte set, and if set pte discovered only after
> taking spinlock, the page will be freed, not leaked.

Oh, right. I rather meant pages that are leaked in case of a failure. My bad.

> Whereas, this patch leaks page for every single !pte_none case. This will build up over time
> as long as vmalloc called.
> 
> > 
> >> Should we set data->pages[PFN_DOWN(addr - data->start)] = NULL 
> >> and free non-null elements later in __kasan_populate_vmalloc()?
> > 
> > Should the allocation fail on boot, the kernel would not fly anyway.
> 
> This is not boot code, it's called from vmalloc() code path.

FWIW, it is called from rest_init() too.

> > If for whatever reason we want to free, that should be a follow-up
> > change, as far as I am concerned.
> > 
> We want to free it, because we don't want unbound memory leak.

Will send v5.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aBomoDkNgiEAJjgX%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
