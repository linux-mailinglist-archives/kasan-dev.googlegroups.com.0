Return-Path: <kasan-dev+bncBC3JRV7SWYEBBHP4Q3ZAKGQEPSF7JUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 475E9158448
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 21:33:36 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id c7sf5448914ioq.18
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 12:33:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581366814; cv=pass;
        d=google.com; s=arc-20160816;
        b=bKO9RZSPMQisUIFS+sBUKthKhnt+rlXGy2s5jPl+1sGnN5rNc88/D9pgbaE1XgrQ/l
         s8DY6yEkKIh1xlmWjkgyqWsdsP8P8YCaHZFcng53NWRjP8TmDV5wVxz0375l2zAuz831
         QNt6y/HLWQTot9TiLXwbK8jBq0bKwUS07xY86TrGOSjAqqxufSrl4l77Ios+xFARUUVs
         UyRz4WWXygz1hbIsrV50UuXvDFclah01a44LEZfdDPTCbsCmJMAKhG7OvcH98dEXzu1c
         +1N9YXWkRV/bNUJx1pAgUSin5nr+6IUalOFqQGtMRidK3l0u/ZFbCMRAnbPM2vumJpIs
         HqsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=knmgHtwg4PAFiCQo1cg5GYfV62YxIt+SKjIs271vreE=;
        b=RySFtMFPB/z58cwulat1+IUme6pXzRQwt/mUV9LsseDufZXOQK8GHmVDOmra61YOGp
         9pJAC0iTxC0B1iiXnSvodBRfnSaVud9hEF7xtf44MKqBnvfHnTkgEcP7cMT895DKUhw3
         DOcmaGxS7x0IpM9gSyMXxUfB684Jtgjtev1AXU2mZQqSm2xVraWaf0jpuVBUkNHrm485
         XVSMQ3Tr+BKxlyA2sr07fQ4S6J6lDkocq3ZG5Hu/Dr940PklhAhEhc52TaTatfPm4QyM
         +i172ZhMp5ClLRqzgSKl3vDyfHb04bqLWWIqejH7E4XZqsLwYTf7L1KuopZWCE7TV256
         7oEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b="Qv9gH/CX";
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=knmgHtwg4PAFiCQo1cg5GYfV62YxIt+SKjIs271vreE=;
        b=EKPbiR/RrrWt+3hBq4lrBwd0AgUKWEje5TIcs7+LS5D6+rsl4FQI5t6dAqqhYdw2RE
         kB0mPFiICLQPfbPuwqKoMUA8s374h7E3Bm1fKqgtagVcs6ucPn1vz2LRBvzkk3ocf/gY
         ipUJoPrkVO4s0y1HJET3Ri1IsDrouweGxJL/SSmusXuooyWYeWzuhV5UrQCPM2xtrGZW
         YGSrPdkj8/yEwthhhsK0zbcYZBFQwhh4bGjh/rXTBl+eBF2WI9hVvNjV29FhGQ3M1gY5
         UPGJ9PG1K3mClAb3bDv3pDgrG8rYckrv70MYvUDB0/M4LhV8hZOTWE27kX0tyZwJVeFH
         fbIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=knmgHtwg4PAFiCQo1cg5GYfV62YxIt+SKjIs271vreE=;
        b=Fj++KPbUcNEw47m9Ymm8y7StoEqtYZrbjHDP83E+rB6G/hAskXI1eHmUIJxDy8qSvU
         SE7EBpmtUupC68qkn8J5v9FBSG0qEKpmCJF47zxIpPd95A7n+BktcvHXCkMPIgIfjbwU
         4HCAOG2tYnIg/DnXmTCGP+cibhzVrfDiKXbbf0T0P+y+5j8s1AHFn1+okQNLVZRxyEA0
         Zol5guMpJpoLrSPF3cOfrp0ZUdzyeH1kotQiPevmSqwEPuAsMTcDIm6QrDIgrpVQg2Ew
         p5JCf2xqGW9Q3+4WwlulivlQOxfkupy1ZNFo7h0KAeFvG8D+OD9ECHLyrMqdT5LK1OPO
         dEiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVALJbKBs4OEGylIU9cNScts1AClofeV/h6/hsOgFeHf77HtftP
	ss9FCbT/0zpOeIRfpLBdQLo=
X-Google-Smtp-Source: APXvYqxYl37TbqWlsIGmdQDT2VdZPLqUrh9jizQOJzCbEDdP3u8LHDKPsssuuzZIf5T0pkNUBijMtQ==
X-Received: by 2002:a05:6e02:5c3:: with SMTP id l3mr3354717ils.260.1581366813745;
        Mon, 10 Feb 2020 12:33:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8c10:: with SMTP id o16ls1962253ild.6.gmail; Mon, 10 Feb
 2020 12:33:33 -0800 (PST)
X-Received: by 2002:a05:6e02:ea9:: with SMTP id u9mr3246227ilj.40.1581366813386;
        Mon, 10 Feb 2020 12:33:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581366813; cv=none;
        d=google.com; s=arc-20160816;
        b=I5qBGTtOWBIMKOAUY0PZfS1bluZ5iD+gp7upHqGO5vrU7GU7xAVDCE4BLqb55jRKTd
         4xNHjJ7j9FfvrtWKEoJ/6SWHM+WsuIOCPolrLgwHYa9D61AaUImPcnv7lduRjlRdINYS
         3fw26Zof8djwF97G9iHHsNRSV/fWX/FlNOHeAo6YBTgzD0loFYIGUrXsxJYW5oe+tq6Q
         nRRrsKPLKYlSBRp6PVNVmxwBMHI1HA6S57/9rRhG9S+1/ao7sap5vejSGWWF68bR6Gz9
         ggfKlpQVCEHZghm3QzOFr6IjQijVzEjMCpgyLkJXIlPxIJB8ofom9X45I6t3xBeNk2fb
         qbbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :dkim-signature;
        bh=vG1mkAjNS0IUY82t2fwR1dyk1+GFCsDem1vS5EXCY2Y=;
        b=S2Y53wcrrTxS2exT4/Debv2SD+wACALcup7a0lTWot8P/Ka/ptoxVy+BnYPmgeOwoJ
         Ye/xPb7NYCV7O5Mx+b0dfHs8NqBXat7avzPwa1arezQasYx+EolhnZ7MOVPzMa4x7WTd
         lZePIf0JhItBGmZ45D1G6ETXOyc7nFd2f8dkr8tKhTLmSb3a2p31v85zhqe/onp2zqte
         o3UVKWNiGgSu5ntyDXwTym9dqr/LSwI6HOVQY1KRj9yxFOmIsdZAOACBFaqLLIx59peY
         TYV8WanYwOqJAiTM/3alJcxoUvMO4Zd7qOPyz3pd7iZ0ZRiOfvfl2MYNuS8+isPKacH5
         Z+Qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b="Qv9gH/CX";
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id i4si76269ioi.1.2020.02.10.12.33.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Feb 2020 12:33:33 -0800 (PST)
Received-SPF: pass (google.com: domain of boris.ostrovsky@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 01AKWMF6068971;
	Mon, 10 Feb 2020 20:33:30 GMT
Received: from aserp3030.oracle.com (aserp3030.oracle.com [141.146.126.71])
	by aserp2120.oracle.com with ESMTP id 2y2jx5ydhf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=FAIL);
	Mon, 10 Feb 2020 20:33:30 +0000
Received: from pps.filterd (aserp3030.oracle.com [127.0.0.1])
	by aserp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 01AKS7x6173225;
	Mon, 10 Feb 2020 20:33:29 GMT
Received: from userv0122.oracle.com (userv0122.oracle.com [156.151.31.75])
	by aserp3030.oracle.com with ESMTP id 2y26htm81x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 10 Feb 2020 20:33:29 +0000
Received: from abhmp0001.oracle.com (abhmp0001.oracle.com [141.146.116.7])
	by userv0122.oracle.com (8.14.4/8.14.4) with ESMTP id 01AKXSlZ011490;
	Mon, 10 Feb 2020 20:33:28 GMT
Received: from bostrovs-us.us.oracle.com (/10.152.32.65)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Mon, 10 Feb 2020 12:33:27 -0800
Subject: Re: [PATCH v3 3/4] xen: teach KASAN about grant tables
To: Sergey Dyasli <sergey.dyasli@citrix.com>, xen-devel@lists.xen.org,
        kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Juergen Gross <jgross@suse.com>,
        Stefano Stabellini
 <sstabellini@kernel.org>,
        George Dunlap <george.dunlap@citrix.com>,
        Ross Lagerwall <ross.lagerwall@citrix.com>,
        Andrew Morton <akpm@linux-foundation.org>
References: <20200207142652.670-1-sergey.dyasli@citrix.com>
 <20200207142652.670-4-sergey.dyasli@citrix.com>
From: Boris Ostrovsky <boris.ostrovsky@oracle.com>
Autocrypt: addr=boris.ostrovsky@oracle.com; keydata=
 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
 Jg6OxFYd01z+a+oL
Message-ID: <22a1a10d-a323-b039-639a-6fee6c32fad6@oracle.com>
Date: Mon, 10 Feb 2020 15:34:05 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.1
MIME-Version: 1.0
In-Reply-To: <20200207142652.670-4-sergey.dyasli@citrix.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9527 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 phishscore=0
 bulkscore=0 adultscore=0 malwarescore=0 suspectscore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2001150001 definitions=main-2002100148
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9527 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 malwarescore=0
 priorityscore=1501 adultscore=0 phishscore=0 impostorscore=0 spamscore=0
 bulkscore=0 lowpriorityscore=0 mlxscore=0 suspectscore=0 clxscore=1015
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2001150001
 definitions=main-2002100148
X-Original-Sender: boris.ostrovsky@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b="Qv9gH/CX";
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates
 141.146.126.78 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
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



On 2/7/20 9:26 AM, Sergey Dyasli wrote:
> From: Ross Lagerwall <ross.lagerwall@citrix.com>
>
> Otherwise it produces lots of false positives when a guest starts using
> PV I/O devices.
>
> Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
>


Reviewed-by: Boris Ostrovsky <boris.ostrovsky@oracle.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/22a1a10d-a323-b039-639a-6fee6c32fad6%40oracle.com.
