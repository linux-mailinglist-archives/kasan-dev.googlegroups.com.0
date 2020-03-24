Return-Path: <kasan-dev+bncBAABBY7P5DZQKGQEV75Q4BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E488719169E
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 17:40:04 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id c7sf15568162iog.13
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 09:40:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585068003; cv=pass;
        d=google.com; s=arc-20160816;
        b=xpKP1JG5xbeenN8mNCCk0xg0arcUmuCtyae0j46N/n8I26/hLv+/zTc9V4V9JmSwAl
         fxrbXTL6LVViw5ccBvHpLeB6YhnuelIUZP5oGWmAK4aD9jKnQc1xHV8TghdX5g54n3P3
         oCwSPHVxmniALiMcfFO4Zu96+XBMAPue+M4lfUIoe71CPqwvh2qhF9BbJ4ZLujXufPqi
         O1lg8/ho9yxm6KEqfk3iq0w4QAdEuJfAVYIkSUkf9fIYltPSTjtDDlrUyFCeohBjDlo0
         1zXHt+2uUQPO0ETDJndrVuntlatlQhiIkHMGkfiUwcgV8DgxeQeTvXTORxN7L0yM4uyP
         QC2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=C5lxubAG2jnQQRxvFDrn9ZWOXn2VUDN3QsFSslDQRqA=;
        b=UZ9DARR0FO48Q9y/MpvAv0sf/M9lDTPMRuYWpewSge2QQlLiilm3jKSIO8bGmOq7En
         Wcl4tTFFrxCnc6R5ojq2FWEcdbRXEq9zGWItvDwfnJ5T2Go+u0rpUUL5/g05j5P3H6Bb
         HlRN/cE6pDtR27NDz3wCVXsdJmYN9otpqeFuASIY0jcQshmnf4BxuLoShmTcYCTXSEPd
         0Minfqf8BY4W7AWAFJny8NkCBffbLPLOAVx1W0Kl72zzCDWaQMz5X5/32xWFhrnc4E2p
         js8/2ZgsKxIlS9kJzzWK2cv91MFfCe3SIMAQtcILokqb21JxD4StKYF8zC/4sP4NfOgZ
         uhzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=gg6emeKg;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C5lxubAG2jnQQRxvFDrn9ZWOXn2VUDN3QsFSslDQRqA=;
        b=KxDfWNgeaGIJzIEiRM3sIhwt3bMWulpPIVdeoaUuG9hR/iXnTLUrxIJtQdS4yfGIc3
         Y2z/mTPZwA5S5fRqCKMkC5KYlSwY81chlt/L5920Vf8ex/PdKqVsTyEaZYSngsZjXCh7
         4o/xTQQhGc2nHu7opJ0prGrTbo11RzZpru53UZkb0j1726b3ZBkrCgGqeFRELtqadzK4
         fESilnSoNRIktxQ/M0opzZLNSanDlV/umd292EBzrqhulxYgNAGERUQOS6In1WXxIMb7
         NGjCsy+ERBgL7ON2bsUoAR93Mnk/U1PKNZNfBTEeiqFZL+0M805CzdxAbOp1TXtdeAcz
         JTfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C5lxubAG2jnQQRxvFDrn9ZWOXn2VUDN3QsFSslDQRqA=;
        b=DOvtQdugbAzJrMWbf8/AyFOYTVdvP3Ukm8EKzSwYqvHarh6iO8t/QRnBRxTQnC9+fe
         YV9jL68Un9IW1kN5Gq5RdEO257wrma8IY/TG43HF3qDuF0qqzF+JlCpomZP6OEnE2BdF
         H1tq2Ih+G9EAfvdZcOJLtgNR+mKpKIE1o8uiRZjO+wqZ/MFPRYbodrg0Xdfk/yJbwsrU
         gRYmxC2C9YcgnAiFnSy4VrUr9+g2nXb2DCNF8UaUT0mtB+oDTE63T0vOyr4Z115rXcVi
         H5Zqp9jlqm+RI6i+J2lvecri+aXSSM8mEJuKCXu5g4j0nBWViLW/RNN7B4+HyMwc6hWE
         Aj+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ25x24w3GUZmDbuJatl0tvnBwSTVIMBrmesrCcSGKwRLZ4/6+nZ
	kbUyR9WtIafJLLyVy1ubORE=
X-Google-Smtp-Source: ADFU+vsfKZOHaa5wCq3W/txukhedBwbZ8FUtTLCpSFUjM0nIeH71NMKVg6WUvVvO11xiG+VDWVhY+w==
X-Received: by 2002:a92:3a0b:: with SMTP id h11mr27824771ila.4.1585068003470;
        Tue, 24 Mar 2020 09:40:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c610:: with SMTP id i16ls939128jan.11.gmail; Tue, 24 Mar
 2020 09:40:03 -0700 (PDT)
X-Received: by 2002:a02:52c3:: with SMTP id d186mr25102323jab.119.1585068003186;
        Tue, 24 Mar 2020 09:40:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585068003; cv=none;
        d=google.com; s=arc-20160816;
        b=MMx9N8Vcvrb9ysHJkbnUlir+gju+c97pEfuhux08OGsAIgrVgE0in5n7jC8tpgNgFy
         25/ZJN62Eo+OivRF+eeC7m5iMFleijpD8nnZdEUmkIQuV0WfUskiRQDXsqcxR9YP5+NP
         +hrjWly9s7YADr3mIi0Hcx1T6vgXsac+x7/Dl6ptR7xAZsBHwJlSn3dGuAeiH0GgsApV
         b5zVl/fT88M7SuX01ERbc4Of+RxdUrVeCBpSOWLk/xdMwL0UUN+ACV55OTBJiMG4l3oJ
         sMpyTIfEzljxPEGNpz5w1G49hKyt8zot0Nhhm1xT2ueRJEL7zVvJnsbGMC5z4+clJ6Ie
         Ueiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=Z05suOHf2IDzsq2FPAO2+DX7KrqPxW6csjVKUUkFIXw=;
        b=CsqoasgCUyvnePFFIOri3o0Br44AEmr1v4AMMESq+tsgliB17si0LaP7S6bkn04/De
         YZGOhg2DU4E3J+D3fMdWaeTnZP9m2uGWWkaUFKic6MRb8CgnR3375QN77qnfALAdmcCT
         iDpAyX5odCJYIvDsHtfaTAKJYm9kx7RodZV+rVhsELe6F9veZNoUFHT7T66PL80BX9J7
         qAThAHCzOT74ODVFu81XJdxT8a43hNDEBM6CCa4ETSMMjw1EyNDfhUbLeKEb0rekCGhj
         LyodHffk0uCvi/YaoxiPQCBo/Bgs7WscTkMXDP3vH5oAx0PlVRyCoJ4dwEfU0YIRM9sj
         AWug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=gg6emeKg;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2130.oracle.com (userp2130.oracle.com. [156.151.31.86])
        by gmr-mx.google.com with ESMTPS id s201si1245219ilc.0.2020.03.24.09.40.03
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Mar 2020 09:40:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of alan.maguire@oracle.com designates 156.151.31.86 as permitted sender) client-ip=156.151.31.86;
Received: from pps.filterd (userp2130.oracle.com [127.0.0.1])
	by userp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 02OGdEdY166419;
	Tue, 24 Mar 2020 16:40:00 GMT
Received: from userp3030.oracle.com (userp3030.oracle.com [156.151.31.80])
	by userp2130.oracle.com with ESMTP id 2ywabr5ef0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 24 Mar 2020 16:40:00 +0000
Received: from pps.filterd (userp3030.oracle.com [127.0.0.1])
	by userp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 02OGKTKa091634;
	Tue, 24 Mar 2020 16:40:00 GMT
Received: from userv0121.oracle.com (userv0121.oracle.com [156.151.31.72])
	by userp3030.oracle.com with ESMTP id 2yxw4pmjd7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 24 Mar 2020 16:40:00 +0000
Received: from abhmp0011.oracle.com (abhmp0011.oracle.com [141.146.116.17])
	by userv0121.oracle.com (8.14.4/8.13.8) with ESMTP id 02OGdwIG007862;
	Tue, 24 Mar 2020 16:39:58 GMT
Received: from dhcp-10-175-162-99.vpn.oracle.com (/10.175.162.99)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Tue, 24 Mar 2020 09:39:57 -0700
Date: Tue, 24 Mar 2020 16:39:50 +0000 (GMT)
From: Alan Maguire <alan.maguire@oracle.com>
X-X-Sender: alan@localhost
To: Patricia Alfonso <trishalfonso@google.com>
cc: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com,
        dvyukov@google.com, mingo@redhat.com, peterz@infradead.org,
        juri.lelli@redhat.com, vincent.guittot@linaro.org,
        linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org
Subject: Re: [RFC PATCH v2 1/3] Add KUnit Struct to Current Task
In-Reply-To: <20200319164227.87419-2-trishalfonso@google.com>
Message-ID: <alpine.LRH.2.21.2003241635230.30637@localhost>
References: <20200319164227.87419-1-trishalfonso@google.com> <20200319164227.87419-2-trishalfonso@google.com>
User-Agent: Alpine 2.21 (LRH 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9570 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 suspectscore=3
 spamscore=0 mlxlogscore=999 adultscore=0 phishscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2003020000 definitions=main-2003240087
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9570 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 suspectscore=3
 lowpriorityscore=0 malwarescore=0 phishscore=0 priorityscore=1501
 clxscore=1015 adultscore=0 mlxscore=0 mlxlogscore=999 bulkscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2003020000 definitions=main-2003240087
X-Original-Sender: alan.maguire@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=gg6emeKg;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates
 156.151.31.86 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
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


On Thu, 19 Mar 2020, Patricia Alfonso wrote:

> In order to integrate debugging tools like KASAN into the KUnit
> framework, add KUnit struct to the current task to keep track of the
> current KUnit test.
> 
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> ---
>  include/linux/sched.h | 4 ++++
>  1 file changed, 4 insertions(+)
> 
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 04278493bf15..1fbfa0634776 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -1180,6 +1180,10 @@ struct task_struct {
>  	unsigned int			kasan_depth;
>  #endif
>  
> +#if IS_BUILTIN(CONFIG_KUNIT)

This patch set looks great! You might have noticed I
refreshed the kunit resources stuff to incorporate
feedback from Brendan, but I don't think any API changes
were made that should have consequences for your code
(I'm building with your patches on top to make sure).
I'd suggest promoting from RFC to v3 on the next round
unless anyone objects.

As Dmitry suggested, the above could likely be changed to be
"#ifdef CONFIG_KUNIT" as kunit can be built as a
module also. More on this in patch 2..

> +	struct kunit			*kunit_test;
> +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> +
>  #ifdef CONFIG_FUNCTION_GRAPH_TRACER
>  	/* Index of current stored address in ret_stack: */
>  	int				curr_ret_stack;
> -- 
> 2.25.1.696.g5e7596f4ac-goog
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.LRH.2.21.2003241635230.30637%40localhost.
