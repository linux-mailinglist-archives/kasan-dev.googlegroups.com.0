Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLHO5OMAMGQETKVZXEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 481495B3189
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Sep 2022 10:19:57 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id y7-20020a7bcd87000000b003b338001a4bsf241648wmj.2
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 01:19:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662711597; cv=pass;
        d=google.com; s=arc-20160816;
        b=nDlOLJ+W+z5KGZct1iSTJ3a16h2l3KBdaCsd4YknrUjHClS5VtasGqIo406IHkQpPK
         Tdefnu3+o3XHSRvq2byufBpJrhD94OxTnpeDdnwhrYglQk8Fti8sWyU7M3f0dEJqrCsh
         X42hlMqiwf1EbCVCSdwtDUeTgRv6TJMvVhfC8qARg0uQqYftZLMdQpa3mb0TmbqRN/Rn
         ySkcELmEJetgO1uHVzmUX9bvmHHgm0xz2mxgJrM/Hu5rQ7zcdOzpIKSxi7SZgdt24xt5
         qiaUrCI12QNW1wOFp0tmKFOpM84LzcaFWmiObGpJzDo8nhpybIrD0a6Lhsot9tRwb2dH
         huDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=o1mOmiN9nU4msV0SmsRHpbVZ4V4s4EHTKPoi+DihLWk=;
        b=d2cCVZi21QK4UIX6s+8t3BflQ/qdbMq8ZaLuB1yz4WPGoRTheSOS1H/PVUeueYv+A/
         upAkboVAK/Zcq+hoyMuhAfvEs9UYpgy8KOVCMQd3GEUDdMFPRmqqZm7N4Aj3AEyJqZw3
         QcL1TEz4F6eMp3m03Eb7hJOvI4aY3E24AEv3BIFJKTIisqEKgoFxACgSeHiK0k/LgieK
         PHe+7SpXCHe6yQ7lYU6TS0Xjpt6063I07n3kvtdpDHa+IRs/LHTgj73AsO0HpvZIBqaR
         FcjgB4ycTj21CBxUDSOTdwAtvV+NaRFkPTXKJPAsigTwA5VbhaTHNDDIDNTuh5JzRg97
         pKQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dMC9Cl2U;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date;
        bh=o1mOmiN9nU4msV0SmsRHpbVZ4V4s4EHTKPoi+DihLWk=;
        b=T2WIj9iaXwwYNqC5CV5+hrLTSjkP76mU6zrdcVu32ga7eqqfjcK95rRKHkQ8kPIspC
         jcrFUGMOC2LC0B9YTuWTnK2KSPi95gcNGlSfE99hXX9zU8sGfzy4VebhN/5Q+rLrZG+c
         hjNr+nh1VWH9e1oObmNefuLKldW2JF4QjFrJm8NzYSUgjkZIGqWWtFvvgORSrFDl5nai
         SGFPqH58KX/kfA4feKkozabUBcVMGqtpz1HyHJVOJ9M+9fJl8EWHXyHbr4dlxN3DIYVv
         Th41a4a1qsuoaP+PSB6USQYeyaE3JKVJrcQhCfUBNbw1njCqXQybT+FeR77NUta91Zgf
         BWUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=o1mOmiN9nU4msV0SmsRHpbVZ4V4s4EHTKPoi+DihLWk=;
        b=I84VZ37PyXhmu2UK4gP/5EJGUQjPmwribRIFfajIXKVQJrorLcOZH6Qfg4aTQcUoWi
         8xg0hWHuWxNQc3RBua88jjU3G/0aFH1NWtLOtje5O7hphaUGrD8vuSMbMtyaHP0plpRw
         Nmk4DO8/AX8hvG29vjHBgF7XKD3RCERbZFPnqhVajXV/pzRt7MWIsjLZZhQedIVenDXu
         YNZGexisWwld3zeYxXUrNPwLIqQcnrcXXELhXUnwRp9sIEedC0NhOEyCPWdUFLV57Xh1
         TZsXUL5aoDYJ2cG9uQI1bDzYNm9F4IFZwnKFZ37oAVCTHQZkGYrqcVBHoqVMtGYY8U1f
         5Ltg==
X-Gm-Message-State: ACgBeo1++mz5fsB+7cmnqPveaBNxll/jSUh7ZGyPci14ef2i7BFcyqxK
	Z6GiN2gErNkw1RyrY4/YXmc=
X-Google-Smtp-Source: AA6agR5Ku8a5P6m49otR8+XPteKdDA7ExgbHjR7KMUkSd5Ycbb8fqg2oSR3MKJtXS3FNkNy2wX0lIg==
X-Received: by 2002:a05:600c:3b25:b0:3b3:1f73:daff with SMTP id m37-20020a05600c3b2500b003b31f73daffmr4414443wms.129.1662711596677;
        Fri, 09 Sep 2022 01:19:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce96:0:b0:3a5:1ad:8654 with SMTP id q22-20020a7bce96000000b003a501ad8654ls1356176wmj.2.-pod-control-gmail;
 Fri, 09 Sep 2022 01:19:55 -0700 (PDT)
X-Received: by 2002:a05:600c:3583:b0:3a7:eeaf:62d3 with SMTP id p3-20020a05600c358300b003a7eeaf62d3mr4613591wmq.170.1662711595424;
        Fri, 09 Sep 2022 01:19:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662711595; cv=none;
        d=google.com; s=arc-20160816;
        b=m9bsQs+p/V+M5EpL+u5TF5ux/Pil/qdG4cmePJo89wfrezwnpk+ekyz0SsrPpwatLp
         Q4KdHn+3VnI25aJypp/8CqfI5EAA0po/nX3xFqeszlee8Q84Pwyg0jlL2kp855ppezEE
         3UgLMvNM0q7q6gxBx+obvIGPqDsv32MYyvqHblcc5RYXWevv2U6FhkLLfMWIs+Mk1BBJ
         iXpSn1TVHHeDDGmuI1LHm/EhegNg7f6n8gQz683wAiP1InH0yLmRAmjxMGeAQOG2g0zf
         pi5gXpFs60QdWGXyQd9JsdxifvxmH3e4/ANoFd3zMdeH9jlXG1TvMTLrvDJnxMmDk5wH
         NX6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=M80nuH0as/dyuPHdT1nX8UsUUmqoa+KIEZcH7oWzmKc=;
        b=epiWH0J2H3mP9h2uTdLScxfiMgf7fFuDB3F7ivtCFl/54YvvD7IpGJewFuSx9K1V97
         awzKaFihQ5XOk76R4OpD23MfdppiEnPoCXGADZ3zLKCaXtu7CtaQRSpRdjdHEiisSIj8
         7Xib0PNWtG9ICoZf3gBF6xK8eeh46jxxYI3hSH5xTqui18vQwE1+p0BqVtoxNMQp9VxY
         UQSlQKkz3rudhldhZ4Ydp25sJJQ6tq8OCWqwjNQaWOsAVrVz/au5/nzn56w2h2pm73g/
         QgW8HsJVI4+ZQqwSOTGS06SOFSF4Yd2SqfTdOe00oyD8PzgoT7EqWAaMBDuYFUD7Ntg9
         oYtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dMC9Cl2U;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id bn11-20020a056000060b00b002256e922345si74468wrb.0.2022.09.09.01.19.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Sep 2022 01:19:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id n17-20020a05600c3b9100b003b3235574dbso715034wms.2
        for <kasan-dev@googlegroups.com>; Fri, 09 Sep 2022 01:19:55 -0700 (PDT)
X-Received: by 2002:a05:600c:1c16:b0:3a6:b11:79be with SMTP id j22-20020a05600c1c1600b003a60b1179bemr4491777wms.203.1662711594959;
        Fri, 09 Sep 2022 01:19:54 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:1d1e:ddcd:2020:36c2])
        by smtp.gmail.com with ESMTPSA id p12-20020a5d68cc000000b00228a6ce17b4sm1265073wrw.37.2022.09.09.01.19.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Sep 2022 01:19:54 -0700 (PDT)
Date: Fri, 9 Sep 2022 10:19:47 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Liu Shixin <liushixin2@huawei.com>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: Re: [PATCH] mm: kfence: convert to DEFINE_SEQ_ATTRIBUTE
Message-ID: <Yxr3I6Ru2WUGzEWn@elver.google.com>
References: <20220909083140.3592919-1-liushixin2@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220909083140.3592919-1-liushixin2@huawei.com>
User-Agent: Mutt/2.2.6 (2022-06-05)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dMC9Cl2U;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, Sep 09, 2022 at 04:31PM +0800, 'Liu Shixin' via kasan-dev wrote:
> Use DEFINE_SEQ_ATTRIBUTE helper macro to simplify the code.
> 
> Signed-off-by: Liu Shixin <liushixin2@huawei.com>

Reviewed-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 15 ++-------------
>  1 file changed, 2 insertions(+), 13 deletions(-)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 8c08ae2101d7..26de62a51665 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -719,24 +719,13 @@ static int show_object(struct seq_file *seq, void *v)
>  	return 0;
>  }
>  
> -static const struct seq_operations object_seqops = {
> +static const struct seq_operations objects_sops = {
>  	.start = start_object,
>  	.next = next_object,
>  	.stop = stop_object,
>  	.show = show_object,
>  };
> -
> -static int open_objects(struct inode *inode, struct file *file)
> -{
> -	return seq_open(file, &object_seqops);
> -}
> -
> -static const struct file_operations objects_fops = {
> -	.open = open_objects,
> -	.read = seq_read,
> -	.llseek = seq_lseek,
> -	.release = seq_release,
> -};
> +DEFINE_SEQ_ATTRIBUTE(objects);
>  
>  static int __init kfence_debugfs_init(void)
>  {
> -- 
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yxr3I6Ru2WUGzEWn%40elver.google.com.
