Return-Path: <kasan-dev+bncBAABBNUC32OQMGQEGKXSO7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 597E065F960
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Jan 2023 03:02:32 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id t13-20020a056902018d00b0074747131938sf509579ybh.12
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Jan 2023 18:02:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672970551; cv=pass;
        d=google.com; s=arc-20160816;
        b=mzvtaaC+TS6jEqqYU3HcxNX6AdTByNQIoALxD6nnkRcZ8PvH5lnPErwIdLQtOE47/s
         OoQka4ROHsjEtP4pFJgd1FFBN65dPRbuALhewu6vySm04Eifn2vNr/6Qd3R4lUpSRz7o
         vJQ0U8kr8F8oZPmSCr5v4iqLIpqiHjyHFRv9sN+EdCMsgrLmggXw5yCawK/MWWUpOrE5
         51Pmh9qers7PT8YZa8T5/qwmrCxHMvKer8K372atGyPxhSIvVhYnMgq+IwBY1FMaBaA5
         O9hYP43AnG93oVOIyXFDv5CqoG2AHbdSj5NZA0Hm3absaoNJBndvAmm+pWo3aLSSxXok
         HrHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:feedback-id:message-id
         :user-agent:references:in-reply-to:subject:cc:to:from:date
         :mime-version:dkim-signature;
        bh=dFjTMYZnctchJ72mwnFjVprAhuaE6vpZboGw/rBf61s=;
        b=KArpFtewrtiVT6kGyUrgiIbpMcIhr9veQHR0dw1YLFcmlHQ+n/4t4t1tNh/3+yA6Bu
         rvSt0GB9QtdKl0iTRLMOPDAbBShZUurCq9Hq8ZKaZ2PVDAPTWJs/8BNohYiQUIal8b6k
         rtS22/UKciLI/LeaApxikZP6OS5x/XAYNhmWGxlI90Kzngj+gwzAEHmteMRDVQy9BYaN
         K9yoLnwLcx8XuyA2eU5uAnZGJTzIGKPzWXLsFvchIPqcW6Owj+knRpcdwU3PlPZWcK/l
         XjSDKmgP0JQTGnOhnck0dYbyw8qKFok99O5L08I7uKOee2GQL/duALBa36SQEc6T4D5r
         Jy5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=OTSv+DlU;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Qh0aaAYS;
       spf=pass (google.com: domain of 0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.20 as permitted sender) smtp.mailfrom=0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :message-id:user-agent:references:in-reply-to:subject:cc:to:from
         :date:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=dFjTMYZnctchJ72mwnFjVprAhuaE6vpZboGw/rBf61s=;
        b=qGhUvgs5aM3t32vEpW45K3wJaVUKdbk6UmEkcIL7+dtOiHNpztOlo0tL5hJCbR3gxY
         D3PnWPeuGV4WBNFAvhIBfkKKWZ6omshFiXfUeUsILocPhiSAo0vbkRTE2cDe8SMG8wCr
         fOGIfSGo3W+WIDxCsk4qEU4Mk794dTfzvIHwtP+zn8/DhXVsrMJEDQrS6dMBDtPCSIy6
         5GZHw4+zC5vTwLJ3yVlzG3tis3mX7YWaI5u7Pb4nm3V++56JYk9kgod96PDkzFh6vCoC
         AdUHl2sGgnk2nAnC6qwrem3fBUbjfjAzC+eOOhScMvS8GSgFDaSx9/38oXQTm1AhY/df
         hU0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:feedback-id
         :message-id:user-agent:references:in-reply-to:subject:cc:to:from
         :date:mime-version:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dFjTMYZnctchJ72mwnFjVprAhuaE6vpZboGw/rBf61s=;
        b=pouLiWixCAzqWt27Tu6ZOA1PK9TrTV3M+pZxrCkkIjwh+b9vvIJwPBZdSPFj0VD30h
         dqO/eWRyEo0qzOzp/jgV9aTshCUy3LuyM8irn+9yQgbLej3y5T+Axyt8uZRsQetLI27R
         CPByaJElTkYzJUMwSCGOAHTCMkcyMesK6m0nd3eq5EsfOehVT/YhIRZ6E0Nyb2BewrHC
         G0s19vjLyrQmRh/oJf2Mcss9N7PuTJMgPH5peiy5ceYde7br0ACHk+qksrZYgUm/NJxP
         7zz6Xq0ZvT+/iMfh+QMveomTdCac+ghAnGuD4a0zooahMeOxfC+s7pnKSOgJ5kw5bECg
         J8Xw==
X-Gm-Message-State: AFqh2krOx14fvWCjQWN9TqhD+lxz98m12lRP8Jlxo805EKCg5lQ/u5m+
	eQxf4RQVfM//j7HfC3XCh1g=
X-Google-Smtp-Source: AMrXdXuKttRJnu80cCiCqdvKY7ElSa5uC1s69NEYWY9dPtQa9hM6JCfSbYeXA6HYpCXFe4wQgdOkUA==
X-Received: by 2002:a0d:c2c1:0:b0:4ad:5c08:7e67 with SMTP id e184-20020a0dc2c1000000b004ad5c087e67mr1632472ywd.75.1672970551033;
        Thu, 05 Jan 2023 18:02:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:d81:b0:3fe:c52c:dd9a with SMTP id
 da1-20020a05690c0d8100b003fec52cdd9als243030ywb.4.-pod-prod-gmail; Thu, 05
 Jan 2023 18:02:30 -0800 (PST)
X-Received: by 2002:a81:78c5:0:b0:468:77ab:900d with SMTP id t188-20020a8178c5000000b0046877ab900dmr42465168ywc.7.1672970550489;
        Thu, 05 Jan 2023 18:02:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672970550; cv=none;
        d=google.com; s=arc-20160816;
        b=Wzl2IybeO1WJiT4GzguzBtk+Q5IHcQRRxWaSt7Lm89z+iGafIJ5ktN3QF2nIZWkm5W
         lWwFzx07W9GkpJq3718C1kLmp4Sn27cGJrSysyVWfgsBOmyNU6+oOecxPxwuZ5H35Ghu
         an+Ip1T192eP/pfXuBcnZuE2IWW8ag9HJlPajRsXPaQsx13X/CriMAZhktp3wfFdNrzE
         ajimLErTI1w08FAmvioqOf7Mq1bDoFg8njn+y2XeCp755uQgTHFaDCfmS/pp842wXWjt
         k4FM9b0iE2r3cgGrDcm9q4/WMBDxUW1W7zN7hNsEUWmT4Kq/xbn+iKjYq459pOasG4fE
         WJYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:message-id:user-agent
         :references:in-reply-to:subject:cc:to:from:date:mime-version
         :dkim-signature:dkim-signature;
        bh=K2hl0SfPWQQ28j56wQsOOvclozCcGcv1dHqwKncoTUU=;
        b=hPjlajkPJcEU6DtZTGr2gVTPpBavIBDI/tNbJBhE3OukfsrsVAGZkT00mZzoOjJURM
         vLUl+N69+QajdwmVIH3Lk0lN6yrmSdkjY6l157yHD2Slr78oY74jXTG694XgjsJxomBN
         9hS4Q5yEFwdDE/5OnV/oe5oJCmEBFzswMUSxR+RlHguEx4mndovmk4ZlfHMvxO6JeTOv
         5z6reFHnQCNMTHCBPOpdiQV0vHdURtK8xtAqcGoGv5RvZdYn5Q0EoMmlHlcHxfOyT8w8
         O/oHXbclQ8KN4bniuJNAp5cQBJnitwNd6wgyMBPNm6w7Nr7QSSWmIFh1Awq8L6nm6Rz6
         hpMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h header.b=OTSv+DlU;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Qh0aaAYS;
       spf=pass (google.com: domain of 0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.20 as permitted sender) smtp.mailfrom=0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
Received: from a27-20.smtp-out.us-west-2.amazonses.com (a27-20.smtp-out.us-west-2.amazonses.com. [54.240.27.20])
        by gmr-mx.google.com with ESMTPS id cl27-20020a05690c0c1b00b003f5fa41badbsi2721975ywb.2.2023.01.05.18.02.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Jan 2023 18:02:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000@ses-us-west-2.bounces.aaront.org designates 54.240.27.20 as permitted sender) client-ip=54.240.27.20;
MIME-Version: 1.0
Date: Fri, 6 Jan 2023 02:02:28 +0000
From: "'Aaron Thompson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ingo Molnar <mingo@kernel.org>
Cc: Mike Rapoport <rppt@kernel.org>, linux-mm@kvack.org, "H. Peter Anvin"
 <hpa@zytor.com>, Alexander Potapenko <glider@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Andy Shevchenko <andy@infradead.org>, Ard
 Biesheuvel <ardb@kernel.org>, Borislav Petkov <bp@alien8.de>, Darren Hart
 <dvhart@infradead.org>, Dave Hansen <dave.hansen@linux.intel.com>, David
 Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, Ingo
 Molnar <mingo@redhat.com>, Marco Elver <elver@google.com>, Thomas Gleixner
 <tglx@linutronix.de>, kasan-dev@googlegroups.com, linux-efi@vger.kernel.org,
 linux-kernel@vger.kernel.org, platform-driver-x86@vger.kernel.org,
 x86@kernel.org
Subject: Re: [PATCH v2 1/1] mm: Always release pages to the buddy allocator in
 memblock_free_late().
In-Reply-To: <Y7aq7fzKZ/EdLVp3@gmail.com>
References: <010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@us-west-2.amazonses.com>
 <20230105041650.1485-1-dev@aaront.org>
 <010001858025fc22-e619988e-c0a5-4545-bd93-783890b9ad14-000000@email.amazonses.com>
 <Y7aq7fzKZ/EdLVp3@gmail.com>
User-Agent: Roundcube Webmail/1.4.13
Message-ID: <0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000@us-west-2.amazonses.com>
X-Sender: dev@aaront.org
Content-Type: text/plain; charset="UTF-8"; format=flowed
Feedback-ID: 1.us-west-2.OwdjDcIoZWY+bZWuVZYzryiuW455iyNkDEZFeL97Dng=:AmazonSES
X-SES-Outgoing: 2023.01.06-54.240.27.20
X-Original-Sender: dev@aaront.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@aaront.org header.s=ude52klaz7ukvnrchdbsicqdl2lnui6h
 header.b=OTSv+DlU;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=Qh0aaAYS;       spf=pass
 (google.com: domain of 0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000@ses-us-west-2.bounces.aaront.org
 designates 54.240.27.20 as permitted sender) smtp.mailfrom=0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000@ses-us-west-2.bounces.aaront.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=aaront.org
X-Original-From: Aaron Thompson <dev@aaront.org>
Reply-To: Aaron Thompson <dev@aaront.org>
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


On 2023-01-05 02:48, Ingo Molnar wrote:
> * Aaron Thompson <dev@aaront.org> wrote:
> 
>> For example, on an Amazon EC2 t3.micro VM (1 GB) booting via EFI:
>> 
>> v6.2-rc2:
>>   # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
>>   Node 0, zone      DMA
>>           spanned  4095
>>           present  3999
>>           managed  3840
>>   Node 0, zone    DMA32
>>           spanned  246652
>>           present  245868
>>           managed  178867
>> 
>> v6.2-rc2 + patch:
>>   # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
>>   Node 0, zone      DMA
>>           spanned  4095
>>           present  3999
>>           managed  3840
>>   Node 0, zone    DMA32
>>           spanned  246652
>>           present  245868
>>           managed  222816   # +43,949 pages
> 
> [ Note the annotation I added to the output - might be useful in the
> changelog too. ]
> 
> So this patch adds around +17% of RAM to this 1 GB virtual system? That
> looks rather significant ...
> 
> Thanks,
> 
> 	Ingo

It is significant, but I wouldn't describe it as being added. I would 
say that the system is currently losing 17% of RAM due to a bug, and 
this patch fixes that bug.

The actual numbers depend on the mappings given by the EFI, so they're 
largely out of our control. As an example, similar VMs that I run with 
the OVMF EFI lose about 3%. I couldn't say for sure which is the 
outlier, but my point is that the specific values are not really the 
focus, this is just an example that shows that the issue can be 
encountered in the wild with real impact. I know I'll be happy to get 
that memory back, whether it is 3% or 17% :)

Thanks,
-- Aaron

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0101018584d0b5a3-ea0e4d67-b00f-4254-8e1c-767fcafbec31-000000%40us-west-2.amazonses.com.
