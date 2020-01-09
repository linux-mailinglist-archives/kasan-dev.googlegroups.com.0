Return-Path: <kasan-dev+bncBC3JRV7SWYEBB3XO33YAKGQE6STAUIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B8C01363D5
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jan 2020 00:29:52 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id l13sf154826pgt.5
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 15:29:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578612591; cv=pass;
        d=google.com; s=arc-20160816;
        b=d8rKpmInwRbXqbhTS+wsML4yoFRjvz032tuWR3KKIzQjKFQ8zj+S8ncmN7uji+l/it
         KE7UwBp4UkLvQ9oujVcHa02cLQSy9N77tDRFfmmaek8Y4x20KO0VlIC2rcDsTcds+5Yw
         PyWf7InymB6SbbyDathlcD8BHtt1bqjJfGqqI7VQEseBMPX3cTfQNTAvTBkumY2lhIQ1
         XyuDFwZL/YaOVSJxT+E2mYzxcDmS4HXKRCfWkfnSRp+WRQYjk2FWPkaRu3Fjlm8x+0aE
         ckYt/AmPd9AsU1ZfNkCVRSiv66+8aC/9NEh/zWGj+Sc4YPts5wJ/kvmCvtZCh7ViyQVj
         SBtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language
         :content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=tSolIaxmLSL8W/CfQYyJCZKDxEyDWoQjMsg8YMqIWmo=;
        b=Cj7SpC8tY3lPco+LRNiSs1PYQDTaX1EVZuTS3Gog2kCg3FIo0l/U1j/mtNvcx4VRvs
         6hJO/cKscj07+AbD4878QFJroYkcgBPnTWkps4jC8JR5OEyVXvYSDsarDw30YJfRgwXE
         FlF3hspLPiBar/q2Fw2uTmK/nKOe7YQqOc5MFVC7CdnDbzcePTpaxC9sP8PDq1QYTAdp
         nsQH/CRgT2itrM60VH2RV7+aAnkO6i29kR+0qZwE0wKc9hIcQgnD5KWOSJZYRUGJVaSB
         0KjrHETwcKktd09IWJCeOwbPhyG+nijM2JbagZFOEetLReeEDqvxO9fa1mkH4f+jdiZf
         FnSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2019-08-05 header.b=CpkVOYU9;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-transfer-encoding:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tSolIaxmLSL8W/CfQYyJCZKDxEyDWoQjMsg8YMqIWmo=;
        b=WEZiOiSGGO1hHj0jEoGSffrBf60kpNdzEv6B5SWkH93qLI8r2PWX8G9nEI+h7EDvvn
         qAd/et7YdnIjCwMwGiu7fdHx7WAwnMjA+QY95+kIYbW3v1S1yH2aUdC7Taj2ewztGvSX
         WDA6vOHzIAsJG0ooJVQfTi4M2oZaoPdJXjvBnLlrkbchzjTBG4FN8rOYEraJaJtMVH0t
         570wBqeOgXen8A4iLIj1bKn9KEEgRCdqvAgpuiWjOlexMj9+9f9tXGPf1doHFrX31dp/
         I8blCrkR3y/Ic1ikCILAN+p8GPVFtlypES5vVqMQV3uyrq+KtnzADrEKy4WmygnWe6S1
         zEgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-transfer-encoding
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tSolIaxmLSL8W/CfQYyJCZKDxEyDWoQjMsg8YMqIWmo=;
        b=ClVBACK9u/jfHPZuxl2ws8ifGlZcf0Xk7MeOIPpCJujy/t/nVoI2PNP9o4ifDOykdf
         cZkj6GuG+55fojpw8ALKFrtXqqF0WbORcFpbHZ80TrdkmtqJNiG5+Xs65H3h9KLNqstT
         Ua/lcFLYxPQx2jies0G052j/f2yn4TcUnLA9z2sQcb+WVe4jgXcRsVy1PipElTALb/Is
         XMeodvy4tDLSU4gmgTVe7ZbGcXXgSTQrG0ddDuna6X6BEJIuwFsL11e5mnGEuCLntJTX
         mF27eiyQ7nsKIiG3DBM9Z59SOZaI8kELilpwYMOdYeqc67vACYp4UPzg+Fq5ixA8e2ku
         NV7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUQDOaQ5XCruC9eFjb0RorQFUizygg3gmB/H8C0qiLQMFtTU7uz
	fgz0Pqvc6deOqGgNZ6OHfK8=
X-Google-Smtp-Source: APXvYqx7N8NsyKxvoZL+NmBRkzfOigKrSZQq/J5scR93JzVWAmKpb1fbb5601niNdPSG492UjisB4w==
X-Received: by 2002:a62:7c58:: with SMTP id x85mr455175pfc.76.1578612590880;
        Thu, 09 Jan 2020 15:29:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2703:: with SMTP id n3ls951379pgn.5.gmail; Thu, 09 Jan
 2020 15:29:50 -0800 (PST)
X-Received: by 2002:a62:1548:: with SMTP id 69mr407457pfv.239.1578612590538;
        Thu, 09 Jan 2020 15:29:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578612590; cv=none;
        d=google.com; s=arc-20160816;
        b=gt9g5figBOHls1iqyzH18M3zG2qqTt9EqdvdHa1it1/PlW4uicEyEWMD0vLPYj65Un
         rcjhZBjjqbU38SAuaJ5BI/CUtLd5dLBfzuXeVIl+z33Vw2C8ev5c0R+1E8/nmWqUuI2+
         eM/dlD+tCpGH9doi9eFK6DFSB9KEW4uuAAYVo2zQVptTs7JJTHgchwbcIzV4Vg0ZBigo
         qOf3WUTh4mkEJC8IgeEVFWjd7KqAukERQgnQBMttAyLNSXnX8oph2YsgiNIxG5I4Jth7
         IdtCxTewuLmAy3LFAlfAji9l3XEDfoX5TQ9dCJgqnawPGGA1EYxPfZVmkNjmpN6g0Q06
         VLdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=mRGveEf/LQllrkPFYbXImW1JYkM5dZmKgDk7Iei+h40=;
        b=zKrZlLWjkazzj5xLYJYmcC/H/SwjgNi9C4YZ9Dq3Ry4p6CFNsalJYZvl1YcqIJaHtW
         Mx8FwscmQjpCNPf3AZ0Y8+yY6t0Z5hBiaRPG5dDZo7947t4LZXqz4Vjr51OlINQYW/ep
         dCZ03adGRkrYPA4Y4Xgjx2XJhqoW9VN/wgLoTgMuy1H+3YLxocQO80TSfoNZza4pX5o1
         37PvC7Ff6pibXtpZ1Z1zZyLn/yF2yWNeJ1V6/wb2k8y31b2rJPsyX1FjbPuL59K3bb91
         qw3K+oO8sI7F9vqJ+mi4eDVt0alzVt0J6d4wW8rLhhPSeev2hnmJZqg7k5wImTtgvW2w
         Dvkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2019-08-05 header.b=CpkVOYU9;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2130.oracle.com (userp2130.oracle.com. [156.151.31.86])
        by gmr-mx.google.com with ESMTPS id d12si178383pjv.0.2020.01.09.15.29.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jan 2020 15:29:49 -0800 (PST)
Received-SPF: pass (google.com: domain of boris.ostrovsky@oracle.com designates 156.151.31.86 as permitted sender) client-ip=156.151.31.86;
Received: from pps.filterd (userp2130.oracle.com [127.0.0.1])
	by userp2130.oracle.com (8.16.0.27/8.16.0.27) with SMTP id 009NSmIg192998;
	Thu, 9 Jan 2020 23:29:44 GMT
Received: from userp3030.oracle.com (userp3030.oracle.com [156.151.31.80])
	by userp2130.oracle.com with ESMTP id 2xaj4ue779-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 09 Jan 2020 23:29:44 +0000
Received: from pps.filterd (userp3030.oracle.com [127.0.0.1])
	by userp3030.oracle.com (8.16.0.27/8.16.0.27) with SMTP id 009NO7Bt063938;
	Thu, 9 Jan 2020 23:27:44 GMT
Received: from userv0121.oracle.com (userv0121.oracle.com [156.151.31.72])
	by userp3030.oracle.com with ESMTP id 2xdms0aay4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 09 Jan 2020 23:27:43 +0000
Received: from abhmp0014.oracle.com (abhmp0014.oracle.com [141.146.116.20])
	by userv0121.oracle.com (8.14.4/8.13.8) with ESMTP id 009NReTB004699;
	Thu, 9 Jan 2020 23:27:40 GMT
Received: from bostrovs-us.us.oracle.com (/10.152.32.65)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Thu, 09 Jan 2020 15:27:40 -0800
Subject: Re: [PATCH v1 2/4] x86/xen: add basic KASAN support for PV kernel
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
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
 <20200108152100.7630-3-sergey.dyasli@citrix.com>
From: Boris Ostrovsky <boris.ostrovsky@oracle.com>
Message-ID: <5214cb54-1719-f93b-130f-90c5da31e22a@oracle.com>
Date: Thu, 9 Jan 2020 18:27:38 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.3.0
MIME-Version: 1.0
In-Reply-To: <20200108152100.7630-3-sergey.dyasli@citrix.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9495 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 malwarescore=0
 phishscore=0 bulkscore=0 spamscore=0 mlxscore=0 mlxlogscore=999
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.0.1-1911140001 definitions=main-2001090195
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9495 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 priorityscore=1501 malwarescore=0
 suspectscore=0 phishscore=0 bulkscore=0 spamscore=0 clxscore=1011
 lowpriorityscore=0 mlxscore=0 impostorscore=0 mlxlogscore=999 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.0.1-1911140001
 definitions=main-2001090196
X-Original-Sender: boris.ostrovsky@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2019-08-05 header.b=CpkVOYU9;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates
 156.151.31.86 as permitted sender) smtp.mailfrom=boris.ostrovsky@oracle.com;
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



On 1/8/20 10:20 AM, Sergey Dyasli wrote:
> @@ -1943,6 +1973,15 @@ void __init xen_setup_kernel_pagetable(pgd_t *pgd,=
 unsigned long max_pfn)
>   	if (i && i < pgd_index(__START_KERNEL_map))
>   		init_top_pgt[i] =3D ((pgd_t *)xen_start_info->pt_base)[i];
>  =20
> +#ifdef CONFIG_KASAN
> +	/*
> +	 * Copy KASAN mappings
> +	 * ffffec0000000000 - fffffbffffffffff (=3D44 bits) kasan shadow memory=
 (16TB)
> +	 */
> +	for (i =3D 0xec0 >> 3; i < 0xfc0 >> 3; i++)

Are you referring here to=C2=A0 KASAN_SHADOW_START and KASAN_SHADOW_END? If=
=20
so, can you use them instead?

-boris

> +		init_top_pgt[i] =3D ((pgd_t *)xen_start_info->pt_base)[i];
> +#endif
> +
>  =20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5214cb54-1719-f93b-130f-90c5da31e22a%40oracle.com.
