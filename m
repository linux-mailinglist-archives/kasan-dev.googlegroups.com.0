Return-Path: <kasan-dev+bncBDXL53XAZIGBBMH5ULDQMGQEOSF6XQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id BDB71BCC125
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 10:07:14 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-b4c72281674sf2551470a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 01:07:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760083633; cv=pass;
        d=google.com; s=arc-20240605;
        b=fiIxVt+lvN3FkMJOSapADR5ehwIGYO94hY5vs2U2yKkCRarlUSkcBnv1vNuKXK9MGI
         pMZdrOu0OAFPakVWRDJXzjto6q1bNoPp42e4L5tgHSSfy/fFBvrUehRcHzDYiFRKEpxv
         Z9AUwKU9FZCdMejxg5J7Uz3ANJw+eXQv0e+ML7xQyu+xM9+j74E+xfosh+7xmM5/srBZ
         avKKryCkU5+guTDUiiqJNgFOfpHCkOoJyACDYJgJo/nwgZc/S4MKfwlO2mqmlI7x/Kjp
         V1An6KU2tlJS9iAyYLNXQmcQZmLh5edonvqSBmfpRIOMQDmWdRJPG4OceLll1ZbLw/C8
         sJqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=RvmbgFuJE5WcAxWOlSggcFXGqgRAwYu86yuX1TsXosM=;
        fh=XzGQ+PmhreMuTVUjD20Mq5lPljcRmhyOHme0eg7Xa/k=;
        b=FjRkVynW1cEdn4IjwxRJgVhHtBorjwWljL2KM9/gf3S2Twb5PfyRrtBCTt7Xt1K0y4
         26b5dmar/sjDXe+oKYBTwpSFjbo9/OAb8GuIdgHAuwcW3JHPPSo7NAqpuwGp7sMYq7yL
         eMmEEct/G8dKEMLwmJuszS+H/7HhTkNQH1i1/zu0FZQt78zs8jWkDyFMD8LbSejctGb7
         nNOk1l0ZotDipmlNHoxNEBOCSkMnomfpKYggryrkMznNYIc8tZ0RYC8C69N3r5hUiWe+
         j4Rd7mw5PQXoxLDaHL+7nmt2e4EKAGytQ2JZ6MtkiPdC9gwV3X2ooFfd+2HeKnUcx+Zd
         XvAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=j6G2yvWW;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760083632; x=1760688432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RvmbgFuJE5WcAxWOlSggcFXGqgRAwYu86yuX1TsXosM=;
        b=VagMCkknvVrxVPJAARFdWDl6ASuavx1P1I+JRulYh/MYWL1QFYYQ+PUsAzJexsTt/H
         QykIoiOIfPjBbyYZFNgYfm24Ekuk4LJtrBjNXezmZxpgEjd2ZCTctdW7carGEAAHbgHO
         G/Y4e4Fa6hBKh8BT264Bu3W2DSYcf739cd4aRnr/FjUzUuLaiFVFnTwJJ8GLgmfPG4vg
         sgC3hoeLJEBRzM/aXrKWb9DRPQH7kho8woOAXbLIhZsLRstwOpzKTL2C/cp7bdnV393f
         Ejnd4whZZic/0eHF990ayu5oAZC+iNKK3tJbw+5n7YC7mQLbnvcNIgtMXZUdawRWnM6y
         leng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760083632; x=1760688432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RvmbgFuJE5WcAxWOlSggcFXGqgRAwYu86yuX1TsXosM=;
        b=i46PjEFIK0CdaiX7LBFVcHTcwgyyBcBuyPoGc3FzF3nmZA44ptvye3aFYfMN4xwMaf
         auLTQ8jsAsy2rX3DqyzlT7Dy3K+KQE+qkwThjp63EV2aYouT48cJ+dx1NnAiSkGMjMfB
         DFGYl/tq9YgLuRFD0ozTHoOiB0vRRDa051JJ77acrlsjylWEqzTEOdSjlNPtYqyQjTeQ
         zv5MM7tEjPM7JWcRN5ajseWidz0G44nTPzl9wsokCBnmrraiyWGeRaE0IcXV5+fpuCQ9
         MhEocDvUuCtM42JkQ74Hgn3Y/gJ3MZNB/pkRpR7C1eLLXoPXPuum3R+lc8b3jbBYxnnY
         dMVA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOgJB3b0Bw00400S1hpgbGq+WEK4WLLeK0BsfGGMxUZh9RrKjwoilN7C6GL/RNdB6vNxKCBw==@lfdr.de
X-Gm-Message-State: AOJu0Yxd05FK+XrETpM6n5/lagSinVi3srnmcvJf9tbiGw9sZe944f3z
	4E/zBQSZWJgVvjd4AgXDrh20q89JZZ7IA5Qwy6d5ntsWmPr5jvOVjhBL
X-Google-Smtp-Source: AGHT+IF4tjXQEw0DMYmMSQ8rpUYHWLDRdfiNxPZFGALNfwUzLCqOJjvVuxddIunrzfMRQI9CtOPc7A==
X-Received: by 2002:a17:903:2ecd:b0:28e:cc41:b0df with SMTP id d9443c01a7336-2902741fb25mr116721655ad.61.1760083632429;
        Fri, 10 Oct 2025 01:07:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5K0bJZ7dhGL99o2nMFWbBLc3Kaa0PzwMp0319pZwiB1g=="
Received: by 2002:a17:903:340e:b0:246:570:cbdd with SMTP id
 d9443c01a7336-290356cc142ls15289145ad.2.-pod-prod-02-us; Fri, 10 Oct 2025
 01:07:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWS++fxWR7UTv+jL4gRy2ikcMFrxXKKJQ1QMyg7yCEZt8w0TGJhkGiS3I81uV86bKVPYtq+xB+L6Y=@googlegroups.com
X-Received: by 2002:a17:902:f68d:b0:25d:d848:1cca with SMTP id d9443c01a7336-290273ef145mr148141485ad.35.1760083630784;
        Fri, 10 Oct 2025 01:07:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760083630; cv=none;
        d=google.com; s=arc-20240605;
        b=cfZ3n4uJ8cSnq5jx2qT+tAfayfVAX6StRz7EmyerPnVR5Y2EvIMt+ubHsxLqGIuIKf
         wfjHtmk/y8pWukOXeb+mGwd31tckIMEC73fcSM4cuyCtlFNGgpu2Ndp3BZIE/5divF4B
         xJyNQSIMFAuUQPyZeZfGoBDv2CDGuD0esatc+lIIf4yOLrAcb7R6XL4SWnT933T2csTW
         DbiGQJEYaQTMwp47gASiu7uRvx5otjQ2gyhG7pb4pvDlwlV1Pq/uMoNtfAsp0qDRW0Xa
         h0pqoVuGriVd+f6hrP79MbZtOMxcOYTpmJQDcwOOyqtPKAhpX1GdnB4ZjyqxeeZxA8Y2
         QvaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=1/qr0Ms7LEN+ZoUHPx1IEnEP/EsOxXGU+zPY1uEN6FU=;
        fh=9Z/GQEuiK/Q+MMCwIECfay+RAoWdEmMKaMoNOe1MDXo=;
        b=iUJVtTHkfpGJImulEoDfbTU/geEFFqdWvq7Bo5EbBJki2FvT9xRvRv5SlYsWRXTBvg
         jBvdVJEhEFMAIYiWPD4UqJNdvyHtQzCFvC1OfEZnLSalpil2dxPJxijsLXtFMMZSflDa
         G58H9Isaq7qm0vcMbSnH3PPT4Udj9NPCeGWYgH7UBXYPyBFwNMz/OU/BYMfphrO5id1c
         ReT/97fIzKfMMonBLxUvEwEZyMZEqx9R8kBgIkNbdv0WE5DOj+6KHbp0J7IZ0rd16dJq
         hGUWDGFZ0WClk1krxoRVH73Ffz6Q5Pwh897TiZ//P9pWuhMctPkCjVyw35spLIG3zc3a
         31ZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=j6G2yvWW;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29040994e7bsi801625ad.0.2025.10.10.01.07.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Oct 2025 01:07:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 599KiJvD031684;
	Fri, 10 Oct 2025 08:07:09 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 49nv829j24-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Oct 2025 08:07:09 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 59A879qq012514;
	Fri, 10 Oct 2025 08:07:09 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 49nv829j23-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Oct 2025 08:07:09 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 59A7uiql020975;
	Fri, 10 Oct 2025 08:07:07 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 49nv9n0ueb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 10 Oct 2025 08:07:07 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 59A875Lh51446214
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 10 Oct 2025 08:07:05 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B335320179;
	Fri, 10 Oct 2025 08:07:05 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 36BAD20177;
	Fri, 10 Oct 2025 08:07:05 +0000 (GMT)
Received: from [9.111.16.15] (unknown [9.111.16.15])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 10 Oct 2025 08:07:05 +0000 (GMT)
Message-ID: <335827e0-0a4c-43c3-a79b-6448307573fd@linux.ibm.com>
Date: Fri, 10 Oct 2025 10:07:04 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] mm/kmsan: Fix kmsan kmalloc hook when no stack depots are
 allocated yet
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org,
        Ilya Leoshkevich <iii@linux.ibm.com>
References: <20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com>
 <20251008203111.e6ce309e9f937652856d9aa5@linux-foundation.org>
Content-Language: en-US
From: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
In-Reply-To: <20251008203111.e6ce309e9f937652856d9aa5@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=KrpAGGWN c=1 sm=1 tr=0 ts=68e8bead cx=c_pps
 a=3Bg1Hr4SwmMryq2xdFQyZA==:117 a=3Bg1Hr4SwmMryq2xdFQyZA==:17
 a=IkcTkHD0fZMA:10 a=x6icFKpwvdMA:10 a=NEAV23lmAAAA:8 a=VnNF1IyMAAAA:8
 a=088SzXbCcwtnasAlsdMA:9 a=QEXdDO2ut3YA:10 a=HhbK4dLum7pmb74im6QT:22
X-Proofpoint-GUID: 6u5H5Z_Cfr6xiadmAO8XAYgVd0Gd3Ceo
X-Proofpoint-ORIG-GUID: xhPR6IrF8eCnckm759wuwrhZdEVGFJYo
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDA4MDEyMSBTYWx0ZWRfX1aFYWzzRgWq7
 t301c9U/pZtABrD4AzRt83sHUHTFyeko/JV6aut+5gaWPRgA1+jbDTqxKK7hUoD2FrSgQKflQ28
 mq3S2MB1HmowEFge3ZsSSW0yHYLa5niIRRNiwTA9o1UGRp9CSGGseWiPXioSKTSBj5CR9GVIenw
 3Ta1kGTj9mLHdLYtIA6C4RdBCHCwXG71dDHQjS6B4ZQW9w0DEN5NSEligiVDmrMBnZClASNLzID
 LRcrAUSFtzkusK71Z1A1dw/rTop4WlyBjMA9/Wrgstc0h09512LlGGGRp9WxqA3D5a1UDJZGzL6
 NcydzGl4R5Oow6zgiWZBBWv/EsEcfxTWdbnNcTyOPbBhTv064pbXqByjUY9Dg2jWWHiTE60PQE+
 GOPEAwH4cYrbMKeIF3fMMaGVJ15U7w==
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-10_01,2025-10-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 suspectscore=0 phishscore=0 adultscore=0 lowpriorityscore=0 clxscore=1015
 priorityscore=1501 impostorscore=0 bulkscore=0 spamscore=0 malwarescore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2510020000 definitions=main-2510080121
X-Original-Sender: aleksei.nikiforov@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=j6G2yvWW;       spf=pass (google.com:
 domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On 10/9/25 05:31, Andrew Morton wrote:
> On Tue, 30 Sep 2025 13:56:01 +0200 Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com> wrote:
> 
>> If no stack depot is allocated yet,
>> due to masking out __GFP_RECLAIM flags
>> kmsan called from kmalloc cannot allocate stack depot.
>> kmsan fails to record origin and report issues.
>>
>> Reusing flags from kmalloc without modifying them should be safe for kmsan.
>> For example, such chain of calls is possible:
>> test_uninit_kmalloc -> kmalloc -> __kmalloc_cache_noprof ->
>> slab_alloc_node -> slab_post_alloc_hook ->
>> kmsan_slab_alloc -> kmsan_internal_poison_memory.
>>
>> Only when it is called in a context without flags present
>> should __GFP_RECLAIM flags be masked.
>>
>> With this change all kmsan tests start working reliably.
> 
> I'm not seeing reports of "hey, kmsan is broken", so I assume this
> failure only occurs under special circumstances?

Hi,

kmsan might report less issues than it detects due to not allocating 
stack depots and not reporting issues without stack depots. Lack of 
reports may go unnoticed, that's why you don't get reports of kmsan 
being broken.

I'm not sure what exactly causes me to hit this issue, but I reproduce 
it pretty reliably on one s390x machine and two x86_64 machines. I 
didn't try more different machines yet.

Here's how I reproduce it on Fedora 42 x86_64 machine using podman.

I've got following files in same directory:

$ ls
busybox.init  busybox.patch  debug.config  kmsan.config 
kmsan.Dockerfile  qemu.sh
$ cat busybox.init
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys

cat <<!


Boot took $(cut -d' ' -f1 /proc/uptime) seconds

         _       _     __ _
   /\/\ (_)_ __ (_)   / /(_)_ __  _   ___  __
  /    \| | '_ \| |  / / | | '_ \| | | \ \/ /
/ /\/\ \ | | | | | / /__| | | | | |_| |>  <
\/    \/_|_| |_|_| \____/_|_| |_|\__,_/_/\_\


Welcome to mini_linux


!
exec /bin/sh
$ cat busybox.patch
diff --git a/libbb/appletlib.c b/libbb/appletlib.c
index d9cc48423..a0c502fde 100644
--- a/libbb/appletlib.c
+++ b/libbb/appletlib.c
@@ -718,8 +718,8 @@ static int find_script_by_name(const char *name)
         return -1;
  }

-int scripted_main(int argc UNUSED_PARAM, char **argv) 
MAIN_EXTERNALLY_VISIBLE;
-int scripted_main(int argc UNUSED_PARAM, char **argv)
+int scripted_main(int argc UNUSED_PARAM, char **argv) 
MAIN_EXTERNALLY_VISIBLE //;
+//int scripted_main(int argc UNUSED_PARAM, char **argv)
  {
         int script = find_script_by_name(applet_name);
         if (script >= 0)
diff --git a/scripts/kconfig/lxdialog/check-lxdialog.sh 
b/scripts/kconfig/lxdialog/check-lxdialog.sh
index 5075ebf2d..c644d1d48 100755
--- a/scripts/kconfig/lxdialog/check-lxdialog.sh
+++ b/scripts/kconfig/lxdialog/check-lxdialog.sh
@@ -45,9 +45,9 @@ trap "rm -f $tmp" 0 1 2 3 15

  # Check if we can link to ncurses
  check() {
-        $cc -x c - -o $tmp 2>/dev/null <<'EOF'
+        $cc -x c - -o $tmp <<'EOF'
  #include CURSES_LOC
-main() {}
+int main() { return 0; }
  EOF
         if [ $? != 0 ]; then
             echo " *** Unable to find the ncurses libraries or the" 
   1>&2
$ cat debug.config
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_KERNEL=y
CONFIG_GDB_SCRIPTS=y
$ cat kmsan.config
CONFIG_KUNIT=y
CONFIG_KMSAN=y
CONFIG_KMSAN_CHECK_PARAM_RETVAL=y
CONFIG_KMSAN_KUNIT_TEST=y
CONFIG_FRAME_WARN=4096
# CONFIG_PROVE_LOCKING is not set
# CONFIG_LOCK_STAT is not set
# CONFIG_DEBUG_WW_MUTEX_SLOWPATH is not set
# CONFIG_DEBUG_LOCK_ALLOC is not set
# CONFIG_PREEMPT_TRACER is not set
# CONFIG_DEBUG_PREEMPT is not set
# CONFIG_TRACE_PREEMPT_TOGGLE is not set
# CONFIG_DEBUG_VIRTUAL is not set
$ cat kmsan.Dockerfile
FROM fedora:42

RUN dnf update -y ; dnf install -y git bash-completion util-linux nano 
patch \
         qemu qemu-kvm openssl openssl-devel ncurses-devel gcc gcc-c++ 
clang clang++ \
         flex bison bc awk cpio gzip sudo elfutils-libelf-devel pod2html 
glibc-static

RUN useradd -m user ; echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER user
WORKDIR /home/user

RUN mkdir src ; cd src ; git clone --depth=1 --branch v6.17 
https://github.com/torvalds/linux ; \
         git clone --depth=1 https://github.com/mirror/busybox

COPY --chown=user:user busybox.patch /home/user/busybox.patch
COPY --chown=user:user qemu.sh /home/user/qemu.sh
COPY --chown=user:user kmsan.config /home/user/kmsan.config
COPY --chown=user:user debug.config /home/user/debug.config
COPY --chown=user:user busybox.init /home/user/busybox.init

RUN chmod +x qemu.sh ; cd src/linux ; make CC=clang defconfig ; \
         cat ~/kmsan.config >> .config ; cat ~/debug.config >> .config ; \
         make CC=clang -j8

RUN cd src/busybox ; patch -p1 < ~/busybox.patch ; make defconfig ; \
         sed -i -e 's:CONFIG_TC=y:# CONFIG_TC is not set:' -e 
's:CONFIG_FEATURE_TC_INGRESS=y:# CONFIG_FEATURE_TC_INGRESS is not set:' 
.config ; \
         sed -i -e 's:# CONFIG_STATIC is not set:CONFIG_STATIC=y:' 
.config ; \
         make -j8 ; make install

RUN mkdir src/initramfs ; cd src/initramfs ; mkdir -p bin sbin etc proc 
sys usr/bin usr/sbin ; \
         cp -a ~/src/busybox/_install/* . ; cp ~/busybox.init ./init ; 
chmod +x init ; \
         find . -print0 | cpio --null -ov --format=newc | gzip -9 > 
../initramfs.cpio.gz
$ cat qemu.sh
#!/bin/bash
exec qemu-system-x86_64 -m 2G -smp 4 -kernel 
~/src/linux/arch/x86/boot/bzImage -initrd ~/src/initramfs.cpio.gz 
-nographic -append "console=ttyS0" -enable-kvm "$@"
$

I build podman image named "kmsan" using non-root user:
$ podman build -f kmsan.Dockerfile -t kmsan .

And run it using same non-root user and privileged podman container:
$ podman run -it --rm --privileged kmsan

And inside podman container I execute qemu.sh script:
$ ./qemu.sh

Here's kmsan unit-test output I get:

[    4.995020]     KTAP version 1 

[    4.996924]     # Subtest: kmsan 

[    4.998461]     # module: kmsan_test 

[    4.998580]     1..25 

[    5.003992]     # test_uninit_kmalloc: uninitialized kmalloc test 
(UMR report) 

[    5.006948] *ptr is true 

[    5.008519]     # test_uninit_kmalloc: EXPECTATION FAILED at 
mm/kmsan/kmsan_test.c:173
[    5.008519]     Expected report_matches(&expect) to be true, but is false
[    5.016673]     not ok 1 test_uninit_kmalloc 

[    5.019871]     # test_init_kmalloc: initialized kmalloc test (no 
reports)
[    5.022995] *ptr is false 

[    5.026736]     ok 2 test_init_kmalloc 

[    5.029653]     # test_init_kzalloc: initialized kzalloc test (no 
reports)
[    5.033060] *ptr is false 

[    5.037952]     ok 3 test_init_kzalloc 

[    5.040898]     # test_uninit_stack_var: uninitialized stack variable 
(UMR report) 

[    5.044349] cond is false 
  

[    5.045465]     # test_uninit_stack_var: EXPECTATION FAILED at 
mm/kmsan/kmsan_test.c:211
[    5.045465]     Expected report_matches(&expect) to be true, but is false
[    5.052473]     not ok 4 test_uninit_stack_var 

[    5.054740]     # test_init_stack_var: initialized stack variable (no 
reports) 

[    5.061026] cond is true 

[    5.064956]     ok 5 test_init_stack_var 

[    5.067630]     # test_params: uninit passed through a function 
parameter (UMR report)
[    5.073602] arg1 is false 

[    5.074766] arg2 is false 

[    5.075939] arg is false 
  

[    5.077078] arg1 is false 

[    5.078317] arg2 is true
[    5.080043]     # test_params: EXPECTATION FAILED at 
mm/kmsan/kmsan_test.c:262
[    5.080043]     Expected report_matches(&expect) to be true, but is 
false
[    5.086057]     not ok 6 test_params 

[    5.088155]     # test_uninit_multiple_params: uninitialized local 
passed to fn (UMR report)
[    5.093995] signed_sum3(a, b, c) is true
[    5.096099]     # test_uninit_multiple_params: EXPECTATION FAILED at 
mm/kmsan/kmsan_test.c:282
[    5.096099]     Expected report_matches(&expect) to be true, but is false
[    5.107367]     not ok 7 test_uninit_multiple_params
[    5.110155]     # test_uninit_kmsan_check_memory: 
kmsan_check_memory() called on uninit local (UMR report)
[    5.116984]     # test_uninit_kmsan_check_memory: EXPECTATION FAILED 
at mm/kmsan/kmsan_test.c:309
[    5.116984]     Expected report_matches(&expect) to be true, but is false
[    5.126356]     not ok 8 test_uninit_kmsan_check_memory
[    5.128587]     # test_init_kmsan_vmap_vunmap: pages initialized via 
vmap (no reports)
[    5.137961]     ok 9 test_init_kmsan_vmap_vunmap
[    5.140564]     # test_init_vmalloc: vmalloc buffer can be 
initialized (no reports)
[    5.145685] buf[0] is true
[    5.151173]     ok 10 test_init_vmalloc
[    5.154140]     # test_uaf: use-after-free in kmalloc-ed buffer (UMR 
report)
[    5.157541] value is true
[    5.158726]     # test_uaf: EXPECTATION FAILED at 
mm/kmsan/kmsan_test.c:378
[    5.158726]     Expected report_matches(&expect) to be true, but is false
[    5.165473]     not ok 11 test_uaf
[    5.167650]     # test_percpu_propagate: uninit local stored to 
per_cpu memory (UMR report)
[    5.173084] check is false
[    5.174605]     # test_percpu_propagate: EXPECTATION FAILED at 
mm/kmsan/kmsan_test.c:396
[    5.174605]     Expected report_matches(&expect) to be true, but is false
[    5.183281]     not ok 12 test_percpu_propagate
[    5.185632]     # test_printk: uninit local passed to pr_info() (UMR 
report)
[    5.191356] ffff9d1b00367cec contains 0
[    5.193590]     # test_printk: EXPECTATION FAILED at 
mm/kmsan/kmsan_test.c:418
[    5.193590]     Expected report_matches(&expect) to be true, but is false
[    5.200144]     not ok 13 test_printk
[    5.202139]     # test_init_memcpy: memcpy()ing aligned initialized 
src to aligned dst (no reports)
[    5.208531]     ok 14 test_init_memcpy
[    5.210437]     # test_memcpy_aligned_to_aligned: memcpy()ing aligned 
uninit src to aligned dst (UMR report)
[    5.216716]     # test_memcpy_aligned_to_aligned: EXPECTATION FAILED 
at mm/kmsan/kmsan_test.c:459
[    5.216716]     Expected report_matches(&expect) to be true, but is false
[    5.225432]     not ok 15 test_memcpy_aligned_to_aligned
[    5.227044]     # test_memcpy_aligned_to_unaligned: memcpy()ing 
aligned uninit src to unaligned dst (UMR report)
[    5.231774]     # test_memcpy_aligned_to_unaligned: EXPECTATION 
FAILED at mm/kmsan/kmsan_test.c:483
[    5.231774]     Expected report_matches(&expect) to be true, but is false
[    5.236286]     # test_memcpy_aligned_to_unaligned: EXPECTATION 
FAILED at mm/kmsan/kmsan_test.c:486
[    5.236286]     Expected report_matches(&expect) to be true, but is false
[    5.242427]     not ok 16 test_memcpy_aligned_to_unaligned
[    5.244753]     # test_memcpy_initialized_gap: unaligned 4-byte 
initialized value gets a nonzero origin after memcpy() - (2 UMR reports)
[    5.248626]     # test_memcpy_initialized_gap: EXPECTATION FAILED at 
mm/kmsan/kmsan_test.c:532
[    5.248626]     Expected report_matches(&expect) to be true, but is false
[    5.252339]     # test_memcpy_initialized_gap: EXPECTATION FAILED at 
mm/kmsan/kmsan_test.c:538
[    5.252339]     Expected report_matches(&expect) to be true, but is false
[    5.258704]     not ok 17 test_memcpy_initialized_gap
[    5.261660]     # test_memset16: memset16() should initialize memory
[    5.268995]     ok 18 test_memset16
[    5.270905]     # test_memset32: memset32() should initialize memory
[    5.275684]     ok 19 test_memset32
[    5.278033]     # test_memset64: memset64() should initialize memory
[    5.283358]     ok 20 test_memset64
[    5.285848]     # test_memset_on_guarded_buffer: memset() on ends of 
guarded buffer should not crash
[    5.292876]     ok 21 test_memset_on_guarded_buffer
[    5.295048]     # test_long_origin_chain: origin chain exceeding 
KMSAN_MAX_ORIGIN_DEPTH (UMR report)
[    5.299320]     # test_long_origin_chain: EXPECTATION FAILED at 
mm/kmsan/kmsan_test.c:599
[    5.299320]     Expected report_matches(&expect) to be true, but is false
[    5.306978]     not ok 22 test_long_origin_chain
[    5.310383]     # test_stackdepot_roundtrip: testing stackdepot 
roundtrip (no reports)
[    5.317344]  kunit_try_run_case+0x19b/0xa00
[    5.319610]  kunit_generic_run_threadfn_adapter+0x62/0xe0
[    5.322374]  kthread+0x89f/0xb20
[    5.324121]  ret_from_fork+0x182/0x2a0
[    5.326284]  ret_from_fork_asm+0x1a/0x30
[    5.330550]     ok 23 test_stackdepot_roundtrip
[    5.333135]     # test_unpoison_memory: unpoisoning via the 
instrumentation vs. kmsan_unpoison_memory() (2 UMR reports)
[    5.340187] =====================================================
[    5.342896] BUG: KMSAN: uninit-value in test_unpoison_memory+0x146/0x3f0
[    5.345803]  test_unpoison_memory+0x146/0x3f0
[    5.347698]  kunit_try_run_case+0x19b/0xa00
[    5.348883]  kunit_generic_run_threadfn_adapter+0x62/0xe0
[    5.350393]  kthread+0x89f/0xb20
[    5.351322]  ret_from_fork+0x182/0x2a0
[    5.352454]  ret_from_fork_asm+0x1a/0x30
[    5.353527]
[    5.353917] Local variable a created at:
[    5.354968]  test_unpoison_memory+0x40/0x3f0
[    5.356253]
[    5.356716] Bytes 0-2 of 3 are uninitialized
[    5.357896] Memory access of size 3 starts at ffff9d1b003f7ced
[    5.359104]
[    5.359473] CPU: 3 UID: 0 PID: 121 Comm: kunit_try_catch Tainted: G 
               N  6.17.0 #1 PREEMPT(voluntary)
[    5.361551] Tainted: [N]=TEST
[    5.362147] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), 
BIOS 1.17.0-5.fc42 04/01/2014
[    5.363915] =====================================================
[    5.365146] Disabling lock debugging due to kernel taint
[    5.366264] =====================================================
[    5.367559] BUG: KMSAN: uninit-value in test_unpoison_memory+0x23d/0x3f0
[    5.368626]  test_unpoison_memory+0x23d/0x3f0
[    5.369292]  kunit_try_run_case+0x19b/0xa00
[    5.369938]  kunit_generic_run_threadfn_adapter+0x62/0xe0
[    5.370768]  kthread+0x89f/0xb20
[    5.371299]  ret_from_fork+0x182/0x2a0
[    5.371862]  ret_from_fork_asm+0x1a/0x30
[    5.372478]
[    5.372695] Local variable b created at:
[    5.373302]  test_unpoison_memory+0x56/0x3f0
[    5.373896]
[    5.374097] Bytes 0-2 of 3 are uninitialized
[    5.374714] Memory access of size 3 starts at ffff9d1b003f7ce9
[    5.375536]
[    5.375771] CPU: 3 UID: 0 PID: 121 Comm: kunit_try_catch Tainted: G 
  B            N  6.17.0 #1 PREEMPT(voluntary)
[    5.377209] Tainted: [B]=BAD_PAGE, [N]=TEST
[    5.377771] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), 
BIOS 1.17.0-5.fc42 04/01/2014
[    5.378816] =====================================================
[    5.382141]     ok 24 test_unpoison_memory
[    5.384615]     # test_copy_from_kernel_nofault: testing 
copy_from_kernel_nofault with uninitialized memory
[    5.389317] =====================================================
[    5.391106] BUG: KMSAN: uninit-value in 
copy_from_kernel_nofault+0x216/0x4b0
[    5.393125]  copy_from_kernel_nofault+0x216/0x4b0
[    5.394564]  test_copy_from_kernel_nofault+0x146/0x2c0
[    5.396107]  kunit_try_run_case+0x19b/0xa00
[    5.397331]  kunit_generic_run_threadfn_adapter+0x62/0xe0
[    5.398582]  kthread+0x89f/0xb20
[    5.399282]  ret_from_fork+0x182/0x2a0
[    5.400070]  ret_from_fork_asm+0x1a/0x30
[    5.400912]
[    5.401260] Local variable src created at:
[    5.402081]  test_copy_from_kernel_nofault+0x56/0x2c0
[    5.403139]
[    5.403525] Bytes 0-3 of 4 are uninitialized
[    5.404396] Memory access of size 4 starts at ffff9d1b00407ce8
[    5.405579]
[    5.405914] CPU: 0 UID: 0 PID: 123 Comm: kunit_try_catch Tainted: G 
  B            N  6.17.0 #1 PREEMPT(voluntary)
[    5.407990] Tainted: [B]=BAD_PAGE, [N]=TEST
[    5.408620] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), 
BIOS 1.17.0-5.fc42 04/01/2014
[    5.409904] =====================================================
[    5.410823] ret is false
[    5.411962]     ok 25 test_copy_from_kernel_nofault
[    5.426479] # kmsan: pass:13 fail:12 skip:0 total:25
[    5.427361] # Totals: pass:13 fail:12 skip:0 total:25
[    5.428300] not ok 1 kmsan

I've debugged it, and as I previously wrote, the cause is stack depots 
not being allocated when kmsan kmalloc hook is called. Previously sent 
patch fixes these unit-test failures for me.

> 
> Please explain how you're triggering this failure and whether you think
> we should backport the fix into -stable kernels and if so, are you able
> to identify a suitable Fixes: target?
> 
At the moment I don't think any backporting is needed.

> Thanks.

Kind regards,
Aleksei Nikiforov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/335827e0-0a4c-43c3-a79b-6448307573fd%40linux.ibm.com.
