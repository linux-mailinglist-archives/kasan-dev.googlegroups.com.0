Return-Path: <kasan-dev+bncBCSMHHGWUEMBBTWBZGGAMGQEXDBPE4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C9CF8450576
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 14:29:52 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id y124-20020a623282000000b0047a09271e49sf9932497pfy.16
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 05:29:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636982991; cv=pass;
        d=google.com; s=arc-20160816;
        b=zw72jKZKD5mbG8GudS0e8OjADRKlFd2hSnxndrc1tNkRtTSm3wfP5LIKowO/ZzE5Gm
         TxPlqRlNVAhl7wZu0Aeim6IWTCXg1EXtGuSGulSNVGaTlQJbkc5i0uNEUoBz1DW5HQI6
         jqW/a8SY+XqDVZjTTYLsUl86KrUnb9Mym9IHPA6sZN6mDul3M/jsYITlK8t3dZm4LJGg
         DE1QTKzHzIDy0gq3Xgpr2FIZsmWYImIoMf+AksaxwmEUfYWfeoN3VF2f/plI15RwIlCv
         vquEY76Sez2gVumoNoHyAsvvdRvPs8Efe0vvpQHZMnhUKxYF/3J+8EVedex47UmRGE+8
         tVZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PSeWtToEiSgAs2kzH6Tqz+VBqTLlmPNePfBbZhwqRrM=;
        b=yNf1x/Q4ziQUfO2YYcUpXdgk0YT3pVN264LahslzeJANEbDwVkXZa0T56uy/REqVMl
         MDDVdf9mvl9yg1Cu9IoEar2s74aDq2cOzQxuNaJYoaFxt6gApF+B4wqcHSlgZwx/xIBd
         sGjiawN06QjA93fL9DIIvoSRfINh61nqmfbKw+cLuXB48ccgxHqn0xlgrmS+pAPvjBJi
         dav5nZcEfLb5ro68qrAoHDb7dBGr0hVYV8BzCXIG2EdtcK6oaFca91orNZZC/bNNQuO5
         C5YIsw+i9/PTfJSurDqvxqoti+ustya50uz386GyyDU+Vc5v81WtC1qTgnwPDFr+PHat
         yUMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=AleVJa4d;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PSeWtToEiSgAs2kzH6Tqz+VBqTLlmPNePfBbZhwqRrM=;
        b=TaFRXawCF1Qcuav/gUQXCVApaFB+Jh6lbxiwQudZrl+yo6e1CRcGR6I0vnW2bf8WZS
         7sWJyx3kHOv7Eky4vsjzUxYKAztc6FxJMnH8RntN47QMTc/IA3maEcLf0eXVRINAOngL
         Wig4SsbI9xIgMODzIatB4mzoQeeRDqs1Mj23DCw/OGoECz3qdr3VJ7KqviHtkieCM1Iq
         Jxk8X2lpysU27YQpozHSsYUBd0tXCP02WY0LhEMhDCRBLUfEys+BlgNGews5ltWo/pXE
         3qfN8JTuMieOfV43Q6rQmqKTmYzThnxopJ8snRoTnLzLx1InUZn7cHRR/U8usoYy9xHu
         vvng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PSeWtToEiSgAs2kzH6Tqz+VBqTLlmPNePfBbZhwqRrM=;
        b=4/pSD7sxlzWgF0lPG3bRKpUHm9hDo8ahwPYIuG/8Fczzf7DYjkAy/sA3/L2gN1U2Fe
         o3/skwgIC+XPM94N51iS4dA6Gyiwf1Zd7WbKXl41zAM1kusz3OrscqBK2kKhZqI1FBQw
         uESZxLA7VZg/lWnVbdl+lSqUowIS4X0YPoqYrMEovX5tIkO8UW9WcQYjO/hX0RkARtbz
         O+l2juzGhF7esLoqas6jyVfydRvSAjae6VXvcHiDv3VuEPEg2SPTF353Si1F61o3N5EJ
         0D7P6GB4Ej8e7DKVUSIGbXp+Ksl0i71CjB+GgZnNCUhO9FPIloe4YX6dBZyQtNKucgNJ
         +t7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313Vauz8k6vRm6Ec23bViCfiSYzqD0244DzQCL7XM87iqS3YqPa
	GkseBwk8CtfZc0jBMBsw1Sc=
X-Google-Smtp-Source: ABdhPJya9lWv04Q+gMptYncXNEeqPGJMaAn9YAnLLAZBordhqhN+1BXNno9BX0OdRTPeZsxMKWVrLg==
X-Received: by 2002:a05:6a00:1a8f:b0:49f:f5ac:b27a with SMTP id e15-20020a056a001a8f00b0049ff5acb27amr32899944pfv.38.1636982991033;
        Mon, 15 Nov 2021 05:29:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f20c:: with SMTP id m12ls965081plc.3.gmail; Mon, 15
 Nov 2021 05:29:50 -0800 (PST)
X-Received: by 2002:a17:902:8bc3:b0:13e:9d00:a8f5 with SMTP id r3-20020a1709028bc300b0013e9d00a8f5mr35202736plo.79.1636982990409;
        Mon, 15 Nov 2021 05:29:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636982990; cv=none;
        d=google.com; s=arc-20160816;
        b=vbnoAg9WKy26Y3bXVB4ztraRgFUKIADtocWWqgwSgaU1wE3YMoNw9fbCdb2GFoCMt9
         QIJQ1GpzTHlljNuxQCLEe2pMf1DpRx7vh/NyGmb8U5QH3dgXwKdOUBVVutgUSZERfXxy
         8r1+MLE09yOohq2Cais+HdeZx/lhyrgCIRs5x5p2kmTD0IWkjilfhTyhxYRIV7FkD01k
         zmiX8L5oSE2Q78Iq7Yp2/x21w9uzvEv+nzP1hB/YlMUWYb4CZrjDkuF628QGsfPUDpi2
         8h2QZAEm9GWiRsT13GXmy+d/sE8tOvmRBnuDpL2zhB+B/2YT1RiKlmTePhSFJ8fYW2WP
         MFmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xSASduQVtPzP/emfrd+RzN5Fm3/Hk+6ZPxPAcA4/Lgw=;
        b=K/4SrItnF5Cty7pIIMwwtdIEXG5YL7TdH4fPHnURBmbFH/2YX1JOm9M/MXIr7XRO+B
         kaDbqH6dzCP2BOPCzAg4I+QlJ96P8twNd5LCLJcjLr6bWsNR2I/O1+Wxq2cInM2T6/RN
         X43yJhWzjB7pRnvuzcLisDZ33G4W+bYi+VwVA9pEkaF5Jge6hjCvLwGJmb0IIogB+xXV
         eBZ8f+BO9eK1p40/v7bfnCN9mQqC8eM0qKTp4iRnfBv5fJDexIJ5I9uK+miOZYRLcpN8
         eyeuF1F6Hc9BDx6f7Nh0ziQ83jVb60JJ0jP5GND0TTkzbUpxshkOvq3zAiUSujwk5UNq
         DFgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=AleVJa4d;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from alexa-out-sd-01.qualcomm.com (alexa-out-sd-01.qualcomm.com. [199.106.114.38])
        by gmr-mx.google.com with ESMTPS id y2si2066272pjp.2.2021.11.15.05.29.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Nov 2021 05:29:50 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as permitted sender) client-ip=199.106.114.38;
Received: from unknown (HELO ironmsg02-sd.qualcomm.com) ([10.53.140.142])
  by alexa-out-sd-01.qualcomm.com with ESMTP; 15 Nov 2021 05:29:49 -0800
X-QCInternal: smtphost
Received: from nasanex01c.na.qualcomm.com ([10.47.97.222])
  by ironmsg02-sd.qualcomm.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 15 Nov 2021 05:29:49 -0800
Received: from nalasex01a.na.qualcomm.com (10.47.209.196) by
 nasanex01c.na.qualcomm.com (10.47.97.222) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Mon, 15 Nov 2021 05:29:49 -0800
Received: from qian-HP-Z2-SFF-G5-Workstation (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Mon, 15 Nov 2021 05:29:48 -0800
Date: Mon, 15 Nov 2021 08:29:46 -0500
From: Qian Cai <quic_qiancai@quicinc.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Will Deacon <will@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>,
	Mark Rutland <mark.rutland@arm.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>, "Valentin
 Schneider" <valentin.schneider@arm.com>
Subject: Re: KASAN + CPU soft-hotplug = stack-out-of-bounds at
 cpuinfo_store_cpu
Message-ID: <YZJgyve+tQ/+8NDC@qian-HP-Z2-SFF-G5-Workstation>
References: <YY9ECKyPtDbD9q8q@qian-HP-Z2-SFF-G5-Workstation>
 <YY9WKU/cnQI4xqNE@qian-HP-Z2-SFF-G5-Workstation>
 <CACT4Y+bj7JU=5Db=bAafjNKJcezeczzDCTwpKvhhC8kESc5+kQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bj7JU=5Db=bAafjNKJcezeczzDCTwpKvhhC8kESc5+kQ@mail.gmail.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-Original-Sender: quic_qiancai@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcdkim header.b=AleVJa4d;       spf=pass
 (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as
 permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

On Sat, Nov 13, 2021 at 07:49:39AM +0100, Dmitry Vyukov wrote:
> This may be just a bad format string.
> But I don't see kernel/printk/printk.c:2264 doing any printk on
> next-20211110. What's up with line numbers?

Yeah, it is usual that the line number could be off by a few lines
with that .config. It is still in my TODO to dig into the bottom of it
though.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZJgyve%2BtQ/%2B8NDC%40qian-HP-Z2-SFF-G5-Workstation.
