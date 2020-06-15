Return-Path: <kasan-dev+bncBDIZTUWNWICRBI7ST33QKGQERXHQ3GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 30F8A1F9F0E
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 20:08:36 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id c5sf11835907iok.18
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 11:08:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592244515; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZpUV8wRi0jo+9zdvm1bfY386n6Vvp0/I4VIs5kz/CMXjhwLWB+w7foQBIYB7PcplE2
         Gh95CyZmEpuNqW0TGnFAPwqJz1NtgcU3kojF3vtZrcMf0GFAfFqU4AHIDJ8Iy+/10c1w
         caoXOmp0yvesE0Pop2hEu22Mwab0MtkhvS01TAQJDxHq5TK4LqqA+l+2BOlOOwzH/RkY
         873sV/V3m/szmFblDkH8J7YVTpqYMeacdrOfrl2pauTIolEkuqPtASnHzjB8NwmI7zUo
         vtuXgE0wO/N0v+9x6shyF2qPmOyRJv8H/y4Uh3GpDhCZyUcLJAPflI19pRu/AaK2RtWQ
         oIrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=2DpPqeQDoaoiyo3cIzmIr7vweQH7Z0doYsW0QV+BiGk=;
        b=w3K6NC7Cm/BvSwGRykJpFNMkWF8PGm7pd6h0+JVvaSAKFysCB7iXngyXn+84YycK76
         eiM897C8YfZ52wu7juyOx11x1mYtiwwATSJHE5SkiYutGli8jEfu0lvVYivfKsRvbXjq
         1qLihLGAnwa+xV3CnXIx37puCRGpeMYcG7S1Dp3dalJ4YOoeAC23VHewkI/IynN5dc+C
         C4yl/HY7HwRNXIZxCTHp9zl360HHe/64sEDOyIeK2hWByL0jNROEjS11GLoV/n5AvKJ3
         3UODyLqW0NxaiooOZu1kmWazQKeaG8NNkIPLUkclGm6I44vB2p2a6ntEdZDmX8hT10oz
         xN0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=ksIm2T40;
       spf=pass (google.com: domain of dan.carpenter@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=dan.carpenter@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2DpPqeQDoaoiyo3cIzmIr7vweQH7Z0doYsW0QV+BiGk=;
        b=Z0TjmxrjVKeoBTrylUe+B5bPGzUN9k7A7bZMoiblMp+kNhSxsGXrBTZ13jUuaIoDt4
         Gohqu/ND3he7WZ2B3k3Hd6QKiO1nGdhZg2p00D7bJoth9w/jFtHoi40PRbmC4Tvj3chx
         dwTaC2dq+MRFkh7TjFJzD4nh9AnJgBtFUPAH5slLijFWF6xRbushQYj568KozvsaE5/V
         V5JClBSMmxlJ4Y00uLG/5L5DDdQCkypPj9T/sLa6GuKC7oYCAyIMKdTByxD7MUEjmMYU
         PvQmPQ/04CVRFLYqr+6g95eo0ogaMit4z0b9MJgqdJnxGGINod8b2nbjRLVnYJtQVgdd
         fFfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2DpPqeQDoaoiyo3cIzmIr7vweQH7Z0doYsW0QV+BiGk=;
        b=dYfGo7oyEz2b+XgQdGzQU+p75r9JlJINnEr6o3jfSc0I/4DXKpeyrCfLRfK1Ud21Ru
         trOgyp2Y1xnTfGBYUpfBdyrPcZIekj7lOjPQm/dY4NGOpAHMNycPe1W9N9VbPLmG4wUb
         4HM6PxEM24IXq8Vs4gmlNJq8uOgcdnTYEZ+PwncPkRL5Omqjf6ITpMKdVAhBcqU22vuP
         JnFIkpYBQ4fEm/aBk5EQXjBJgwRChBZ3o7Hq2tJaSuTRcvXzxSwCE4r/zZM2NJ1AC7kN
         EYPFQzvHbAIN0gbKoKdngjvqPG7/DlvqaY+LG3Y5nFOEarLdQ3kcqiZa6hRZgiFxyCbZ
         hPqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xuNvc7LevpUuxmHX0AbPg5MjPqFOAbFbxgv5vsV16IiGnmQsN
	D4uWJVUkX+HYyOMFMUHHCrE=
X-Google-Smtp-Source: ABdhPJyKD5rSf3Lu9C1Qf4dnsSynfzrrD5P3TdSYGI1dZ2mIysLrn3txZ0nSLyJiwp97qhmHdO9BOQ==
X-Received: by 2002:a5e:a901:: with SMTP id c1mr28387056iod.167.1592244515218;
        Mon, 15 Jun 2020 11:08:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2b81:: with SMTP id r1ls2717290iov.11.gmail; Mon,
 15 Jun 2020 11:08:34 -0700 (PDT)
X-Received: by 2002:a6b:b503:: with SMTP id e3mr22123570iof.175.1592244514886;
        Mon, 15 Jun 2020 11:08:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592244514; cv=none;
        d=google.com; s=arc-20160816;
        b=q4I+rEzzbvIFBGUE8NQR1ZON0c0HdD+k7hzIKum9IYSMHsjuziRzvLSWyhnFGkUjCz
         OhRJdmMCYejdFTRnzZA63+gR76euYpA8RGZByTadhwlslLV/xLKey6b+aN1xDJZonrfP
         6iTcavXZQPAiKL/m5qDEgNuk8t+n64vltWTMg87tpvh3AUeaVDWToQcaMfIGKl3AQIUA
         5jW1OYSFx3mzoeM6hPCjxh5I9D8kyzaGsYjmmRTWmT9JeR2bJIbJbTIc1Mqv0NXrR4yT
         yze/rYUE2cg8/cg6OttPwJ1pbdyaZfagiJjPcr1iHgTsS4N+vNJUrttdhG1o8AZUdonH
         Mh3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EdV85x/l0ZQB7qs/RGol05XelTO/TGwy+i5Nwcf8gRM=;
        b=u049LGrZYTS41BIKfUQhtl7gS/ViQrYqxjgUWKjWkohZJn9ppVHR4IyEALL/jmFX4f
         2sCU3HuVEJBXhTH/36pT7Y4QSQmIkH08DEbpPzqb0gUhJ/Pfe3AX3gI+QiGBf/t1uuSP
         D9wjKB5zpNpx9aR9wNcHaYc0cjemrHdxTK0/eHN2t3fSWGZBJIhc3YvEIw4vRQoFsaBt
         szRc6zs2j2GgXClEHtA/b2SuQggfVaRzwTUD+SS1JLAv4eyuQPiNEz5EokDuHYjIHoeb
         AVuxvVm2rw0+GJYmaTF/cLklte0HLJeLXCvoUkgNNrk2MWz35V5+Ugthu9Sxnph0ko/A
         jxmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=ksIm2T40;
       spf=pass (google.com: domain of dan.carpenter@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=dan.carpenter@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2130.oracle.com (userp2130.oracle.com. [156.151.31.86])
        by gmr-mx.google.com with ESMTPS id y22si1063813ioc.0.2020.06.15.11.08.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 11:08:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dan.carpenter@oracle.com designates 156.151.31.86 as permitted sender) client-ip=156.151.31.86;
Received: from pps.filterd (userp2130.oracle.com [127.0.0.1])
	by userp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 05FI7hca026496;
	Mon, 15 Jun 2020 18:08:31 GMT
Received: from aserp3020.oracle.com (aserp3020.oracle.com [141.146.126.70])
	by userp2130.oracle.com with ESMTP id 31p6s22cke-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=FAIL);
	Mon, 15 Jun 2020 18:08:31 +0000
Received: from pps.filterd (aserp3020.oracle.com [127.0.0.1])
	by aserp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 05FHwvkZ051587;
	Mon, 15 Jun 2020 18:08:30 GMT
Received: from userv0122.oracle.com (userv0122.oracle.com [156.151.31.75])
	by aserp3020.oracle.com with ESMTP id 31p6de1e1n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 15 Jun 2020 18:08:30 +0000
Received: from abhmp0002.oracle.com (abhmp0002.oracle.com [141.146.116.8])
	by userv0122.oracle.com (8.14.4/8.14.4) with ESMTP id 05FI8G7g031730;
	Mon, 15 Jun 2020 18:08:17 GMT
Received: from kadam (/41.57.98.10)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Mon, 15 Jun 2020 11:08:15 -0700
Date: Mon, 15 Jun 2020 21:07:53 +0300
From: Dan Carpenter <dan.carpenter@oracle.com>
To: Waiman Long <longman@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        David Howells <dhowells@redhat.com>,
        Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
        James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
        David Rientjes <rientjes@google.com>, samba-technical@lists.samba.org,
        virtualization@lists.linux-foundation.org, linux-mm@kvack.org,
        linux-sctp@vger.kernel.org, target-devel@vger.kernel.org,
        linux-stm32@st-md-mailman.stormreply.com, devel@driverdev.osuosl.org,
        linux-s390@vger.kernel.org, linux-scsi@vger.kernel.org, x86@kernel.org,
        kasan-dev@googlegroups.com, cocci@systeme.lip6.fr,
        linux-wpan@vger.kernel.org, intel-wired-lan@lists.osuosl.org,
        linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
        ecryptfs@vger.kernel.org, linux-nfs@vger.kernel.org,
        linux-fscrypt@vger.kernel.org, linux-mediatek@lists.infradead.org,
        linux-amlogic@lists.infradead.org,
        linux-arm-kernel@lists.infradead.org, linux-cifs@vger.kernel.org,
        netdev@vger.kernel.org, linux-wireless@vger.kernel.org,
        linux-kernel@vger.kernel.org, linux-bluetooth@vger.kernel.org,
        linux-security-module@vger.kernel.org, keyrings@vger.kernel.org,
        tipc-discussion@lists.sourceforge.net, wireguard@lists.zx2c4.com,
        linux-ppp@vger.kernel.org, linux-integrity@vger.kernel.org,
        linuxppc-dev@lists.ozlabs.org, linux-btrfs@vger.kernel.org
Subject: Re: [PATCH 1/2] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200615180753.GJ4151@kadam>
References: <20200413211550.8307-1-longman@redhat.com>
 <20200413211550.8307-2-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200413211550.8307-2-longman@redhat.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9653 signatures=668680
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=2 adultscore=0 bulkscore=0
 phishscore=0 malwarescore=0 spamscore=0 mlxlogscore=930 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2004280000
 definitions=main-2006150134
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9653 signatures=668680
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 lowpriorityscore=0 impostorscore=0
 clxscore=1011 mlxscore=0 mlxlogscore=944 priorityscore=1501 phishscore=0
 malwarescore=0 suspectscore=2 spamscore=0 cotscore=-2147483648 bulkscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2004280000 definitions=main-2006150135
X-Original-Sender: dan.carpenter@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=ksIm2T40;
       spf=pass (google.com: domain of dan.carpenter@oracle.com designates
 156.151.31.86 as permitted sender) smtp.mailfrom=dan.carpenter@oracle.com;
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

On Mon, Apr 13, 2020 at 05:15:49PM -0400, Waiman Long wrote:
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 23c7500eea7d..c08bc7eb20bd 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1707,17 +1707,17 @@ void *krealloc(const void *p, size_t new_size, gfp_t flags)
>  EXPORT_SYMBOL(krealloc);
>  
>  /**
> - * kzfree - like kfree but zero memory
> + * kfree_sensitive - Clear sensitive information in memory before freeing
>   * @p: object to free memory of
>   *
>   * The memory of the object @p points to is zeroed before freed.
> - * If @p is %NULL, kzfree() does nothing.
> + * If @p is %NULL, kfree_sensitive() does nothing.
>   *
>   * Note: this function zeroes the whole allocated buffer which can be a good
>   * deal bigger than the requested buffer size passed to kmalloc(). So be
>   * careful when using this function in performance sensitive code.
>   */
> -void kzfree(const void *p)
> +void kfree_sensitive(const void *p)
>  {
>  	size_t ks;
>  	void *mem = (void *)p;
> @@ -1725,10 +1725,10 @@ void kzfree(const void *p)
>  	if (unlikely(ZERO_OR_NULL_PTR(mem)))
>  		return;
>  	ks = ksize(mem);
> -	memset(mem, 0, ks);
> +	memzero_explicit(mem, ks);
        ^^^^^^^^^^^^^^^^^^^^^^^^^
This is an unrelated bug fix.  It really needs to be pulled into a
separate patch by itself and back ported to stable kernels.

>  	kfree(mem);
>  }
> -EXPORT_SYMBOL(kzfree);
> +EXPORT_SYMBOL(kfree_sensitive);
>  
>  /**
>   * ksize - get the actual amount of memory allocated for a given object

regards,
dan carpenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615180753.GJ4151%40kadam.
