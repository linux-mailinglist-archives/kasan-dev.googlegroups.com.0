Return-Path: <kasan-dev+bncBCWK3NXC5AIBBLHFRKCQMGQEBTSBHOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3158E383C02
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 20:15:10 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id p140-20020a25d8920000b0290508c3296a35sf8489673ybg.8
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 11:15:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621275309; cv=pass;
        d=google.com; s=arc-20160816;
        b=qj53oOPOAkq1KCSDWOI763iGr5CnrrkNeYN4ZNe39EhPUo+Ug/kJ/x/B8WWVwqiicX
         sHGi1YJJMkLIYIL8V0RvVPytGD94UZFyBGYYCJkHRfdz0vZjLEYwvrpyGwzHJVsE1rnz
         3TebaLh1HIkOqaHfkraksQWYEDLV0QE4ho2sFAH96aACv6xF4n5o7+bP+Ti7nqIST9Zt
         Au2imj29SHloaZGhGPxB0nhf2YbCU2nQ8jPT8uhrgrcKJWv3SZ8fiiIVvKPcZyqC31r4
         UCCrWafX+xjWG2HkgdBl7nOBLFP7xj/wosb0xirpjZYUh6JD0nWuL4SLr3mV6WU6+QP6
         7gHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=sw2aBg1dLh9Xzh5ax8Kxg3vucVaw6XwIgss/0FAc4DM=;
        b=u7Ib1oBM6DUfd27v8BwVoDfMZ5RpqFPYW84R4GUI66aYtLHEltALi/NSFI/r0jKt57
         yTOG1nc+0jR1UO2bLEubU7HunVP4IZQ/vTFrV0gIIzDlFjvRzLxX3CU/pnrrJ6GG4136
         6pLKk5WeCCw61fliFbfBnjIBFCvc7Dbm1FmfftpH8A7eRAILi0KJgmH1Ta74FFGtjzru
         QFAP3p5LG/7NXLW9NnxDZrxKfCsUa2yl0iFBSXCEW+1cCTIfCl/CYgcFjIpWQiA+ndea
         q8U1yM0+RIf0hGcLTjzHUObrffvLaPVw7DOwPiB3l1IIXuphvNVQXmeMj8C3T0UMuzo/
         VGag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=MszFyo2A;
       spf=pass (google.com: domain of vegard.nossum@oracle.com designates 141.146.126.79 as permitted sender) smtp.mailfrom=vegard.nossum@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sw2aBg1dLh9Xzh5ax8Kxg3vucVaw6XwIgss/0FAc4DM=;
        b=GbYanmcrccxqsQLLfkebUAviWRBKiIsAc5zHGBT5BOr7vpC7Fp6fk+g/Nj3AJMZA4f
         t4nWffbPjPLoW1XMPtKZ3Ws5xwPRAww2VXXZsS9HxdyzvEidkOrYmStwp6axLfM4jqKr
         yzwMQdwqAcaw0IcS38tomqS6mJVM1R+pCjsRkPQ0EN26HMqCkvRulvsvQqujtdfuRqxo
         DzdrfyPG/xIF8RBocrP5fEtv6zray+pgQ81u9jTEoTKQ+Vwzf5naBZSIT2uSTgrBicth
         QUd8766F0cdDNGzjf9Rg5L7vhKaqqLSDL9aodGmGa0ofmwmHJ/h4VjeECjEDZferTr1v
         y6wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sw2aBg1dLh9Xzh5ax8Kxg3vucVaw6XwIgss/0FAc4DM=;
        b=Y9J/UP/ImBJ1gI7KZGSWMBosc0bTFDJT7g9exh+vx6QRTVn2uDMkAk6pnrttcFw19r
         jLNAK5MxweXAMGXSoxekiSW8ZKydIGZlvfztC6Sv+0+DFNkP3sLXycYPq05sF8BooCQx
         ZdiCL6dYw/Euw2G3BvayIzCE4sl2TShBlSCtQGnQgPRj4+EyVqLlonSpa8YG+xRwA1FW
         hOlICTa+LjiHRw8LP6gFygFtvpur25d1hjhWuFEw73HQeM7d7i+hy8zngO4aETNTzhbl
         8gLu3GOJO1yb6mzQCBRkIJqIJ5pdEz6TIyh2PdTryoQuTeg8UGqEP2b9Io8OJ1YeXlhy
         qTYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531fq1oHRNfpe4DAxQpuWq/eY5Uq5Bjy8oa97+9Cjflz5ld4L1yH
	M28NwJj/i2nx+ba0wjo2+lQ=
X-Google-Smtp-Source: ABdhPJws/OpGOJw+NxO+MxNiMgN2ruLw3YZRHYZh3mwF9XQ1Sz98QV2zzyr+AiClWiy7kEivVWB8RA==
X-Received: by 2002:a25:be0c:: with SMTP id h12mr1672989ybk.29.1621275308977;
        Mon, 17 May 2021 11:15:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7bc7:: with SMTP id w190ls8612445ybc.2.gmail; Mon, 17
 May 2021 11:15:08 -0700 (PDT)
X-Received: by 2002:a25:9982:: with SMTP id p2mr1637422ybo.457.1621275308544;
        Mon, 17 May 2021 11:15:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621275308; cv=none;
        d=google.com; s=arc-20160816;
        b=N4zM1QwwhnEJ8Lf4Py20h9JEYpwy/TqJ/CT+5AlRMdK9HyC/C9nUr3OP0Cd5S+rTbs
         A8KxnkYEQ6HVMQHB9+vdFd/WQ4bNV3yK2HuGLhVNB3falEZ2xICSLgvk7ueY43SKrzBc
         K8H3n2GyEkvRwaoP8SwqCaO4MN1OXQwORtnaOYZlvN0+5uB2B2TJoT80kX2LnaiSaErI
         qhkwWYWV/U+Fw4dL7/+yrOo8w1g80XegYEF1G5MZIHYY5fVnUYYWPnSELrUAEII0INEj
         EkZyGa4m7iXElPScaATURxTITQRlG/wbKMTsNDKGrpD41MaXPHyoGphE3hApPLak8QsI
         y75w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=LYLRdgK9/MrLRcKez2xEijp8HDa6c4HXQOuCebl2j4I=;
        b=a+3obYbGtrKrCwSu83sWH3QBNkYGQC/4Vmn+Y5vjcJe9xQygwzr5VFi7bU293bpsNI
         MxRvqof1oKPHSvoyRDDOV6VsxPagpl06dCpik4iNEc8LcRDBKkf2HXak4pSncuLNCiE0
         yu24+Qo6sELJXt5QSbSB+vNvg/YX4xe8Qbh2OtS2ayisUfbthIe355s38qIhm3UUNrjo
         SEaVwWDvS3yyVVxHrQmmJHncBZoIERFh8M9rhxyRhTJ9gVmpQZzcETPrmqNRUzaqOmM4
         xbSSQkPaGvGflHXS4fPS8i1blVOWuY2SRLuONApq4YIiK4RDU9BMpq3GtTVTxE+9O0Az
         iB+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=MszFyo2A;
       spf=pass (google.com: domain of vegard.nossum@oracle.com designates 141.146.126.79 as permitted sender) smtp.mailfrom=vegard.nossum@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2130.oracle.com (aserp2130.oracle.com. [141.146.126.79])
        by gmr-mx.google.com with ESMTPS id l14si1290106ybp.4.2021.05.17.11.15.08
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 May 2021 11:15:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of vegard.nossum@oracle.com designates 141.146.126.79 as permitted sender) client-ip=141.146.126.79;
Received: from pps.filterd (aserp2130.oracle.com [127.0.0.1])
	by aserp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 14HIEJau031441;
	Mon, 17 May 2021 18:15:06 GMT
Received: from aserp3020.oracle.com (aserp3020.oracle.com [141.146.126.70])
	by aserp2130.oracle.com with ESMTP id 38j3tbc5ra-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 17 May 2021 18:15:06 +0000
Received: from pps.filterd (aserp3020.oracle.com [127.0.0.1])
	by aserp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 14HIBps4137735;
	Mon, 17 May 2021 18:15:06 GMT
Received: from userv0122.oracle.com (userv0122.oracle.com [156.151.31.75])
	by aserp3020.oracle.com with ESMTP id 38j646bp30-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 17 May 2021 18:15:06 +0000
Received: from abhmp0007.oracle.com (abhmp0007.oracle.com [141.146.116.13])
	by userv0122.oracle.com (8.14.4/8.14.4) with ESMTP id 14HIF3CJ004559;
	Mon, 17 May 2021 18:15:04 GMT
Received: from [10.175.27.158] (/10.175.27.158)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Mon, 17 May 2021 11:15:03 -0700
Subject: Re: Re: "Learning-based Controlled Concurrency Testing"
To: paulmck@kernel.org, Dmitry Vyukov <dvyukov@google.com>
Cc: syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
From: Vegard Nossum <vegard.nossum@oracle.com>
Message-ID: <5650d220-9ca6-c456-ada3-f64a03007c26@oracle.com>
Date: Mon, 17 May 2021 20:14:59 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9987 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxscore=0 malwarescore=0
 bulkscore=0 mlxlogscore=999 phishscore=0 adultscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2104190000
 definitions=main-2105170126
X-Proofpoint-ORIG-GUID: Q1C9tt0ids0LZtZY0dpmFeAzrYtSlaCX
X-Proofpoint-GUID: Q1C9tt0ids0LZtZY0dpmFeAzrYtSlaCX
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9987 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 lowpriorityscore=0 malwarescore=0
 spamscore=0 priorityscore=1501 suspectscore=0 mlxlogscore=999 mlxscore=0
 impostorscore=0 adultscore=0 clxscore=1011 phishscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2104190000
 definitions=main-2105170127
X-Original-Sender: vegard.nossum@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=MszFyo2A;
       spf=pass (google.com: domain of vegard.nossum@oracle.com designates
 141.146.126.79 as permitted sender) smtp.mailfrom=vegard.nossum@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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


On 2021-05-17 18:44, Paul E. McKenney wrote:
> My hope is that some very clever notion of "state" would allow
> coverage-guided fuzzing techniques to be applied across the full kernel.
> Here are a few not-so-clever notions I have thought of, in the hope that
> they inspire some notion that is within the realm of sanity:
> 
> 1.	The current coverage state plus the number of locks held by the
> 	current CPU/task.  This is not so clever because the PC value
> 	normally implies the number of locks.
> 
> 	It might be possible to do a little bit better by using the
> 	lockdep hash instead of the number of locks, which could help
> 	with code that is protected by a lock selected by the caller.
> 
> 2.	#1 above, but the number of locks held globally, not just by
> 	the current CPU/task.  This is not so clever because maintaining
> 	the global number of locks held is quite expensive.
> 
> 3.	#2 above, but approximate the number of locks held.  The
> 	question is whether there is an approximation that is
> 	both efficient and useful to fuzzing.
> 
> 4.	Run lockdep and periodically stop all the CPUs to gather the
> 	hashes of their current lock state plus PC.  The result is a set
> 	of states, one for each pair of CPUs, consisting of the first
> 	CPU's PC and both CPU's lockdep hash.  Combine this with the
> 	usual PC-only state.
> 
> 	I could probably talk myself into believing that this one is
> 	clever, but who knows?	One not-so-clever aspect is the size of
> 	the state space, but perhaps bloom-filter techniques can help.
> 
> 5.	KCSAN-like techniques, but where marking accesses forgives
> 	nothing.  No splats, but instead hash the "conflicting" accesses,
> 	preferably abstracting with type information, and add this hash
> 	to the notion of state.  This might not be so clever given how
> 	huge the state space would be, but again, perhaps bloom-filter
> 	techniques can help.
> 
> 6.	Your more-clever ideas here!

Somewhat tangential in the context of the paper posted (and probably
less clever), and not based on state... but how about a new gcc plugin
that records which struct members are being accessed? You could for
example hash struct name + member name into a single number that can be
recorded AFL-style in a fixed-size bitmap or kcov-style...

The fundamental idea is to just ignore everything about locking and
concurrent accesses -- if you have the data above you'll know which
independent test cases are likely to *try* accessing the same data (but
from different code paths), so if there's a race somewhere it might be
triggered more easily if they're run concurrently.


Vegard

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5650d220-9ca6-c456-ada3-f64a03007c26%40oracle.com.
