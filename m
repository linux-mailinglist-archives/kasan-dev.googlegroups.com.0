Return-Path: <kasan-dev+bncBDIZTUWNWICRBEEZUL3QKGQEZY5RL3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B9D51FABF2
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 11:10:41 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id t69sf10618427ilk.13
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 02:10:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592298640; cv=pass;
        d=google.com; s=arc-20160816;
        b=QyqMbtPu83UDGPZUqhKzQhvAPHYdjbKotHa/S4qJiviglJVkTtoVAb1ruInuY7EPYw
         AJegQpIB28bVm645w1lshLBnS/JByHkuFjDg2Q9jztKO8WQSEet/dd9ur20TIqtrsWLM
         sE09vr0Xjzx3FVIR21JsXOwueZQI4D9XBYluOKp0LI3dPMiMs+axvv4NVeyCd4UGjX1d
         JIPYBVsIBFAXs2x6MuK1x/A3WLL1uI9bHWUN5U3Eif4gQdr4UWXEbl1cco2DKr5EIIg6
         Q76Xd/Ay3z0v4oxwazpoJw/YwLzVWXdDSH8uVbgteNsQ5vJ0yvLI4oSsHhKy1qA3x9gl
         XXJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=UZROBc5jyQ+USryjsKmbLegkyu1wcJF86u7Oaw2wfq4=;
        b=ABWTVSvgaSQAB4uorr2tEVxTVCCX87xNXUq16Skg2T2JHKiw2PyV7Zlf9JuswHp44h
         5XpHMxjTR5Ae4dorI64T9rfZ1wdHnAMZi/ER01R4F571TomO8LjT5lUDcWSuLuzSlLJw
         OqnemgyqTXgccPR7H+afTKY8XG0gtumPf9NcAF/BfGqpXiK6h3szWaPdn89rCSNwztFU
         lFIzPhPsyTqdzLMoVxYWRHGKBofSiMb5UHrhpHlELXWcxcSHy2Kahnv7DrBJke9PZmFX
         J2f5o8m6QxcxQHM79pxyF4yi9u8pm2WwgXMDPE6P9RiGCm/ZCLVLux/JtiqEBRhv5Hpx
         qsrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=cVx0KE5h;
       spf=pass (google.com: domain of dan.carpenter@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=dan.carpenter@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UZROBc5jyQ+USryjsKmbLegkyu1wcJF86u7Oaw2wfq4=;
        b=IY4EjOmVt/gG1YxblVBCaGfDNkn4d1DP748HrZDIsM/DfcKjF0zaN51E+6qilZyos8
         1r3Vw392fRiyvamDdThXjMkdRt7u7SdPrRsNxGinb8TFr4Kg0OljBeZ8bHbqmhe5KLNn
         IHJgMzWO8DHz+gVFt+xeTAjHcQDzAgMp56+1EU2gzgee4qt+UAAKyOZMlOBiKB9O6k5z
         Lot0m06oh9MhCExyubsDyCAprya+XEL4Xfk0r1H2T3cLYXqVG0sMcEs+DyalLWJvkb3u
         urKg9njRW37LOGJGWJO2xqDTWWVVTDLbbsPFL7r5EkmR8ekLpNJbG2XHijr7KNb9Oiem
         eRQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UZROBc5jyQ+USryjsKmbLegkyu1wcJF86u7Oaw2wfq4=;
        b=gtMG21DrIrHtudjKUdWXUOmVvkWpAVWDKPjAoQz1nCB5BTQzUUp9dGhj50FvmAOI4Z
         CyWKvpX8WCY4SNYLTYvbJQc4ZuAia2iUmXhUVbxMQQmotguYRzvHtp9F8KdIFLgi/qWb
         R6Qgv/bUKQPdPgss2Q5PJzNLEkLvoXgfAF/xK78s/9C4b9w8iZ4aUywpR613YJQQk8OO
         PN5ilj2WJ0SsFrPSZyzV6+yLOsdbDaFuMYItrcTgaDhA6FSqbW+Cfp5sryLG/chmBv69
         6192cHm70D7aKhjFzrRzXdH91sbyAw7jkBFiQlfICNWZSh/vi9kbQ+Ah+77OBPgGyZpd
         3C/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530x8U7stKT65kKkunPo37QceX/u/BTVGeasFnG+zVgVNrx5uMs4
	IC9djSxdKk9ngrCe5ySURuY=
X-Google-Smtp-Source: ABdhPJycax2TJWrCO50N5POGrN25U4dLz/gvR1ndYShdDZ09qZKXY/EXZdlIOcATD1oVAc/vujNRIQ==
X-Received: by 2002:a05:6602:2817:: with SMTP id d23mr1608094ioe.206.1592298640466;
        Tue, 16 Jun 2020 02:10:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:e216:: with SMTP id z22ls3131170ioc.5.gmail; Tue, 16 Jun
 2020 02:10:40 -0700 (PDT)
X-Received: by 2002:a6b:91d4:: with SMTP id t203mr1576443iod.149.1592298640189;
        Tue, 16 Jun 2020 02:10:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592298640; cv=none;
        d=google.com; s=arc-20160816;
        b=tsXqIY4Rx3rvwNOSMYNurQXUNaWJP6zlze8zUIPram9iJNkz6RApIuQ66PFpYTuVq8
         5Q/aqEXl9h1LjeqpoIkXcplRAEEJmfgLX4n4C/Fzy1eoL0qYalpnuTm5sJfLazgWD2vT
         mfELWvtUnEFSdyvxtRnCsXbLclKVVEJb4+dwS4axdOj3bi3Bvs772ldFlFIWcQ2UfSEL
         CFODUY4XGMzyxxfYkCw83fibT9tot6tLk0BiBCPf4zrQLw/LQxF2mO0UtErjQZs4XApo
         ir/JCSrVCW1WYrIbFTB/EMt90+7ah/Na6QSOFTYv52w58bNKPTT4Yti7AIKEAS/lNHms
         qzkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=vHFhOuRLkm8vQDg8Dof4S5HKAiKznh8tBQ+Mr1OID/Q=;
        b=LXQvqsJ2blgoBtYDeALEcfZdswxKO8/qY6zkN3G782DD+AymcR8u3sLqVTczthjcjS
         9WJr/MFXu0kUOMe8ihyi2olAU6gjPlCqwtgveeQUZD1LnOxhi6w40F5SbehbwKq3cDmk
         KNVdemF8Cws21qbTZ0Vqp/a+GwaO9sx6ZtsV5TkUCpYGUtO2k1w+MQ+wlvmb6F6U75eK
         mijJGe7sdsOb5r7/v4rqshVTJRVSJsctUfQrQ4CNCj7M2qHTBCGHwDoKrAV4egpw4q+U
         ioxeIGLGhM7Jg2uYvk6tfJsbz45zBzSz2eTIACJOFNHhs3exws30D9qOj0sG567oWUzy
         q8jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=cVx0KE5h;
       spf=pass (google.com: domain of dan.carpenter@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=dan.carpenter@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2120.oracle.com (userp2120.oracle.com. [156.151.31.85])
        by gmr-mx.google.com with ESMTPS id k1si1067756ilr.0.2020.06.16.02.10.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 02:10:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of dan.carpenter@oracle.com designates 156.151.31.85 as permitted sender) client-ip=156.151.31.85;
Received: from pps.filterd (userp2120.oracle.com [127.0.0.1])
	by userp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 05G93Vcj108652;
	Tue, 16 Jun 2020 09:10:36 GMT
Received: from aserp3030.oracle.com (aserp3030.oracle.com [141.146.126.71])
	by userp2120.oracle.com with ESMTP id 31p6e5wptp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=FAIL);
	Tue, 16 Jun 2020 09:10:36 +0000
Received: from pps.filterd (aserp3030.oracle.com [127.0.0.1])
	by aserp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 05G933ih037660;
	Tue, 16 Jun 2020 09:08:35 GMT
Received: from aserv0121.oracle.com (aserv0121.oracle.com [141.146.126.235])
	by aserp3030.oracle.com with ESMTP id 31p6s6w4s2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Jun 2020 09:08:35 +0000
Received: from abhmp0019.oracle.com (abhmp0019.oracle.com [141.146.116.25])
	by aserv0121.oracle.com (8.14.4/8.13.8) with ESMTP id 05G98O1L002227;
	Tue, 16 Jun 2020 09:08:25 GMT
Received: from kadam (/41.57.98.10)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Tue, 16 Jun 2020 02:08:24 -0700
Date: Tue, 16 Jun 2020 12:08:07 +0300
From: Dan Carpenter <dan.carpenter@oracle.com>
To: Michal Hocko <mhocko@kernel.org>
Cc: Waiman Long <longman@redhat.com>, "Jason A . Donenfeld" <Jason@zx2c4.com>,
        linux-btrfs@vger.kernel.org,
        Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
        David Sterba <dsterba@suse.cz>, David Howells <dhowells@redhat.com>,
        linux-mm@kvack.org, linux-sctp@vger.kernel.org,
        keyrings@vger.kernel.org, kasan-dev@googlegroups.com,
        linux-stm32@st-md-mailman.stormreply.com, devel@driverdev.osuosl.org,
        linux-cifs@vger.kernel.org, linux-scsi@vger.kernel.org,
        James Morris <jmorris@namei.org>, Matthew Wilcox <willy@infradead.org>,
        linux-wpan@vger.kernel.org, David Rientjes <rientjes@google.com>,
        linux-pm@vger.kernel.org, ecryptfs@vger.kernel.org,
        linux-fscrypt@vger.kernel.org, linux-mediatek@lists.infradead.org,
        linux-amlogic@lists.infradead.org,
        virtualization@lists.linux-foundation.org,
        linux-integrity@vger.kernel.org, linux-nfs@vger.kernel.org,
        Linus Torvalds <torvalds@linux-foundation.org>,
        linux-wireless@vger.kernel.org, linux-kernel@vger.kernel.org,
        stable@vger.kernel.org, linux-bluetooth@vger.kernel.org,
        linux-security-module@vger.kernel.org, target-devel@vger.kernel.org,
        tipc-discussion@lists.sourceforge.net, linux-crypto@vger.kernel.org,
        Johannes Weiner <hannes@cmpxchg.org>, Joe Perches <joe@perches.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        linuxppc-dev@lists.ozlabs.org, netdev@vger.kernel.org,
        wireguard@lists.zx2c4.com, linux-ppp@vger.kernel.org
Subject: Re: [PATCH v4 1/3] mm/slab: Use memzero_explicit() in kzfree()
Message-ID: <20200616090807.GK4151@kadam>
References: <20200616015718.7812-1-longman@redhat.com>
 <20200616015718.7812-2-longman@redhat.com>
 <20200616064208.GA9499@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200616064208.GA9499@dhcp22.suse.cz>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9653 signatures=668680
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 malwarescore=0 mlxscore=0
 suspectscore=0 mlxlogscore=781 phishscore=0 bulkscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2004280000
 definitions=main-2006160066
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9653 signatures=668680
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 priorityscore=1501 adultscore=0
 mlxscore=0 phishscore=0 mlxlogscore=814 lowpriorityscore=0 clxscore=1011
 suspectscore=0 spamscore=0 bulkscore=0 malwarescore=0 impostorscore=0
 cotscore=-2147483648 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2004280000 definitions=main-2006160066
X-Original-Sender: dan.carpenter@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=cVx0KE5h;
       spf=pass (google.com: domain of dan.carpenter@oracle.com designates
 156.151.31.85 as permitted sender) smtp.mailfrom=dan.carpenter@oracle.com;
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

On Tue, Jun 16, 2020 at 08:42:08AM +0200, Michal Hocko wrote:
> On Mon 15-06-20 21:57:16, Waiman Long wrote:
> > The kzfree() function is normally used to clear some sensitive
> > information, like encryption keys, in the buffer before freeing it back
> > to the pool. Memset() is currently used for the buffer clearing. However,
> > it is entirely possible that the compiler may choose to optimize away the
> > memory clearing especially if LTO is being used. To make sure that this
> > optimization will not happen, memzero_explicit(), which is introduced
> > in v3.18, is now used in kzfree() to do the clearing.
> > 
> > Fixes: 3ef0e5ba4673 ("slab: introduce kzfree()")
> > Cc: stable@vger.kernel.org
> > Signed-off-by: Waiman Long <longman@redhat.com>
> 
> Acked-by: Michal Hocko <mhocko@suse.com>
> 
> Although I am not really sure this is a stable material. Is there any
> known instance where the memset was optimized out from kzfree?

I told him to add the stable.  Otherwise it will just get reported to
me again.  It's a just safer to backport it before we forget.

regards,
dan carpenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616090807.GK4151%40kadam.
